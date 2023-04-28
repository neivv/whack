use std::mem;
use std::ptr;
use std::slice;

use lde;
use byteorder::{ByteOrder, LE};
use smallvec::SmallVec;
use winapi::um::winnt::{RtlAddFunctionTable, RtlDeleteFunctionTable, RUNTIME_FUNCTION};

use crate::helpers::*;
use crate::insertion_sort;
use crate::near_module_alloc::NearModuleAllocator;
use crate::{GeneratedHook, OrigFuncCallback};

pub use crate::win_common::*;

const JUMP_INS_LEN: usize = 14;
#[inline]
pub unsafe fn write_jump_to_ptr(from: *mut u8, to_ptr: *const *const u8) {
    // We don't use the pointer to pointer here since x86_64 has rip-relative jumps instead.
    // Could technically just have different arch-specific types, but too lazy for that right now.
    *from = 0xff;
    *from.offset(1) = 0x25;
    write_unaligned(from.offset(2), 0u32);
    write_unaligned(from.offset(6), *to_ptr);
}

pub struct ExecutableHeap {
    allocators: Vec<NearModuleAllocator>,
}

impl ExecutableHeap {
    pub const fn new() -> ExecutableHeap {
        ExecutableHeap {
            allocators: Vec::new(),
        }
    }

    /// Function for just allocating some executable memory.
    /// Not guaranteed to be near any specific module.
    pub fn allocate(&mut self, size: usize) -> *mut u8 {
        self.any_allocator().allocate(size)
    }

    fn any_allocator(&mut self) -> &mut NearModuleAllocator {
        if self.allocators.is_empty() {
            let exe_handle = exe_handle() as *const u8;
            self.allocators.push(NearModuleAllocator::new(exe_handle));
        }
        &mut self.allocators[0]
    }

    /// ptr is start,end range to which the returned allocation must be near.
    ///
    /// Returns also the allocator base for unwind info adding.
    fn allocate_near(&mut self, ptr: (*const u8, *const u8), size: usize) -> (*const u8, *mut u8) {
        for alloc in &mut self.allocators {
            if let Some(s) = alloc.allocate_near(ptr, size) {
                return (alloc.base(), s.as_ptr());
            }
        }
        let mut allocator = NearModuleAllocator::new(ptr.0);
        let ret = allocator.allocate_near(ptr, size).expect("Failed to allocate");
        let ret = (allocator.base(), ret.as_ptr());
        self.allocators.push(allocator);
        ret
    }

    /// Returns allocator which started at `base`
    fn allocator_for_base(&mut self, base: *const u8) -> Option<&mut NearModuleAllocator> {
        self.allocators.iter_mut().find(|x| x.base() == base)
    }
}

pub struct UnwindTables {
    tables: Vec<UnwindTable>,
    buffered_function_decls: Vec<RUNTIME_FUNCTION>,
    buffered_unwind_info: Vec<u8>,
    buffered_base: *const u8,
}

struct UnwindTable {
    // NearModuleAllocator base
    base: *const u8,
    // ptr, size in objects
    functions: (*mut RUNTIME_FUNCTION, usize),
}

unsafe impl Send for UnwindTables {}
unsafe impl Sync for UnwindTables {}

impl UnwindTables {
    pub const fn new() -> UnwindTables {
        UnwindTables {
            tables: Vec::new(),
            buffered_function_decls: Vec::new(),
            buffered_unwind_info: Vec::new(),
            buffered_base: ptr::null(),
        }
    }

    fn add_buffered(
        &mut self,
        base: *const u8,
        function: (*const u8, *const u8),
        info: &[u8],
        heap: &mut ExecutableHeap,
    ) {
        if base != self.buffered_base {
            self.commit(heap);
        }
        self.buffered_base = base;
        let mut func = unsafe { mem::zeroed::<RUNTIME_FUNCTION>() };
        func.BeginAddress = u32::try_from((function.0 as usize) - (base as usize)).unwrap();
        func.EndAddress = u32::try_from((function.1 as usize) - (base as usize)).unwrap();
        unsafe { *func.u.UnwindInfoAddress_mut() = self.buffered_unwind_info.len() as u32; }
        self.buffered_function_decls.push(func);
        assert!(info.len() & 3 == 0);
        self.buffered_unwind_info.extend_from_slice(&info);
    }

    pub fn commit(&mut self, heap: &mut ExecutableHeap) {
        if self.buffered_function_decls.is_empty() {
            return;
        }
        let base = self.buffered_base;
        let old_funcs = match self.tables.iter().find(|x| x.base == base) {
            Some(s) => s.functions,
            None => (self.buffered_function_decls.as_mut_ptr(), 0),
        };
        let buffered_func_count = self.buffered_function_decls.len();
        let unwind_info_len = self.buffered_unwind_info.len();
        let funcs_count = old_funcs.1 + buffered_func_count;
        let funcs_size = funcs_count * mem::size_of::<RUNTIME_FUNCTION>();
        let alloc_size = funcs_size + unwind_info_len;
        let allocator = heap.allocator_for_base(base).expect("Invalid unwind info base");
        unsafe {
            let new_info = allocator.allocate(alloc_size);
            let functions_out = new_info as *mut RUNTIME_FUNCTION;
            let unwind_info_out = new_info.add(funcs_size);
            let unwind_info_out_offset =
                u32::try_from((unwind_info_out as usize) - (base as usize)).unwrap();
            for func in &mut self.buffered_function_decls {
                let old = *func.u.UnwindInfoAddress_mut();
                *func.u.UnwindInfoAddress_mut() = old.checked_add(unwind_info_out_offset)
                    .unwrap();
            }

            ptr::copy_nonoverlapping(old_funcs.0, functions_out, old_funcs.1);
            ptr::copy_nonoverlapping(
                self.buffered_function_decls.as_ptr(),
                functions_out.add(old_funcs.1),
                buffered_func_count,
            );
            ptr::copy_nonoverlapping(
                self.buffered_unwind_info.as_ptr(),
                unwind_info_out,
                unwind_info_len,
            );
            self.tables.push(UnwindTable {
                base,
                functions: (functions_out, funcs_count),
            });

            if old_funcs.1 != 0 {
                RtlDeleteFunctionTable(old_funcs.0);
            }
            RtlAddFunctionTable(functions_out, funcs_count as u32, base as u64);
        }

        self.buffered_function_decls.clear();
        self.buffered_unwind_info.clear();
    }
}

struct StackPopSize(usize);

fn is_preserved_reg(reg: u8) -> bool {
    match reg {
        0 | 1 | 2 | 8 | 9 | 10 | 11 => false,
        _ => true,
    }
}

pub struct HookWrapAssembler {
    rust_in_wrapper: *const u8,
    target: *const u8,
    args: SmallVec<[Location; 8]>,
    stdcall: bool,
}

pub struct FuncAssembler {
    buf: AssemblerBuf,
    // (signature_pos, stack_pos)
    // e.g. fn(@stack(2) i32, @eax i32, @ecx i32, @stack(1) i32)
    // would have (0, 2), (3, 1).
    current_stack: SmallVec<[(u8, u8); 8]>,
    preserved_regs: SmallVec<[u8; 8]>,
    arg_num: u8,
    func_offsets: Vec<usize>,
    offset_pos: usize,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Location {
    Register(u8),
    Stack(i16),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AsmValue {
    Register(u8),
    Stack(i16),
    Undecided,
    Constant(u64),
}

/// Allows accessing offset of a constant value from `AssemblerBuf` that was written once
/// `AssemblerBuf::write_fixups` has been called to actually write the constants to memory.
#[derive(Copy, Clone)]
struct ConstOffset(usize);

#[derive(Copy, Clone)]
struct ConstOffsets(usize);

impl Location {
    fn reg_to_opt(&self) -> Option<u8> {
        match *self {
            Location::Register(x) => Some(x),
            Location::Stack(_) => None,
        }
    }

    fn stack_to_opt(&self) -> Option<i16> {
        match *self {
            Location::Register(_) => None,
            Location::Stack(x) => Some(x),
        }
    }
}

impl AsmValue {
    fn from_loc(loc: &Location) -> AsmValue {
        match *loc {
            Location::Register(x) => AsmValue::Register(x),
            Location::Stack(x) => AsmValue::Stack(x),
        }
    }

    /// Gives corresponding `AsmValue` for a function's argument `arg_num`,
    /// when the caller is using the standard Microsoft's calling convention.
    fn for_callee(arg_num: u8) -> AsmValue {
        match arg_num {
            0 => AsmValue::Register(1),
            1 => AsmValue::Register(2),
            2 => AsmValue::Register(8),
            3 => AsmValue::Register(9),
            n => AsmValue::Stack(i16::from(n)),
        }
    }
}

impl ConstOffsets {
    fn to_offset(&self, val: ConstOffset) -> usize {
        self.0 + val.0 * 8
    }
}

impl HookWrapAssembler {
    pub fn new(rust_in_wrapper: *const u8, target: *const u8, stdcall: bool) -> HookWrapAssembler
    {
        HookWrapAssembler {
            rust_in_wrapper,
            stdcall,
            target,
            args: SmallVec::new(),
        }
    }

    pub fn add_arg(&mut self, arg: Location) {
        assert!(self.args.iter().find(|&&a| a == arg).is_none());
        self.args.push(arg);
    }

    fn is_win64_calling_convention(&self) -> bool {
        let expected_regs = [
            Location::Register(1),
            Location::Register(2),
            Location::Register(8),
            Location::Register(9),
        ];
        for (i, arg) in self.args.iter().enumerate() {
            if let Some(reg) = expected_regs.get(i) {
                if arg != reg {
                    return false;
                }
            } else {
                if *arg != Location::Stack(i as i16) {
                    return false;
                }
            }
        }
        true
    }

    pub fn generate_and_write_wrapper(
        &self,
        orig: OrigFuncCallback,
        entry: Option<*const u8>,
        heap: &mut ExecutableHeap,
        unwind_tables: &mut UnwindTables,
    ) -> GeneratedHook {
        let mut buffer = AssemblerBuf::new();

        let orig_ptr = match orig {
            OrigFuncCallback::Hook(s) => Some(s),
            _ => None,
        };
        let (out_wrapper_pos, unwind_info) = self.write_in_wrapper(&mut buffer, orig_ptr);
        if let OrigFuncCallback::Overwritten(orig) = orig {
            buffer.align(16);
            self.write_hook_out_wrapper(&mut buffer, out_wrapper_pos, orig);
        }
        buffer.align(16);
        buffer.write_fixups();

        let code = HookWrapCode {
            buf: buffer,
            unwind_info,
            import_fixup_offset: 0,
        };
        code.write_wrapper(entry, heap, unwind_tables)
    }

    pub fn generate_import_wrapper_code(&self) -> HookWrapCode {
        let mut buffer = AssemblerBuf::new();

        let (out_wrapper_pos, unwind_info) = self.write_in_wrapper(&mut buffer, None);
        let import_fixup_offset = self.write_import_out_wrapper(&mut buffer, out_wrapper_pos);
        buffer.align(16);
        let const_offsets = buffer.write_fixups();

        HookWrapCode {
            buf: buffer,
            unwind_info,
            import_fixup_offset: const_offsets.to_offset(import_fixup_offset),
        }
    }

    /// Orig should be set for call_hook only
    /// Second return value is unwind info.
    fn write_in_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        orig: Option<*const u8>,
    ) -> (AsmFixupPos, Vec<u8>) {
        let is_non_replacing_hook = orig.is_some();

        // Reserve space for calling the rust in wrapper (args + 1 for out wrap + 1 for hook)
        // Always at least 4 for the x64 shadow space.
        let stack_args_amount = (self.args.len() + 2).max(4) << 3;
        let mut stack_reserve_amount = stack_args_amount;
        if is_non_replacing_hook {
            // Reserve space for storing all registers except rsp
            stack_reserve_amount += 15 * 8;
        }
        // | 8 to align stack correctly if it was not.
        let stack_reserve_size = stack_reserve_amount | 8;
        let prolog_start = buffer.buf.len();
        buffer.stack_sub(stack_reserve_size);
        let prolog_end = buffer.buf.len();
        // Adding just the stack sub as unwind info, should be enough
        let unwind_info = [
            0x01, // version = 1, flags = 0
            (prolog_end - prolog_start) as u8, // Prolog size (4)
            0x01, // Unwind code count (Just stack sub)
            0x00, // No frame register
            // Unwind codes
            // Code 0 instruction end offset:
            (prolog_end - prolog_start) as u8,
            // Code 0 data:
            // 2 = Small stack alloc, can represent 8 ~ 128 bytes
            // Should check if it can fit but should never not fit.
            0x2 | ((stack_reserve_size >> 3).wrapping_sub(1) << 4) as u8,
            0x00, 0x00, // Align
        ];

        // At offset past args
        let register_store_offset = stack_args_amount;
        if is_non_replacing_hook {
            buffer.store_registers(register_store_offset);
        }

        let arg_registers = [1u8, 2, 8, 9];
        // Target (hook dyn Fn pointer) param goes to second reg that isn't used or stack
        let value = AsmValue::Constant(self.target as u64);
        let arg_idx = self.args.len() + 1;
        if let Some(&out_wrapper_arg_reg) = arg_registers.get(arg_idx) {
            buffer.mov_to_reg(out_wrapper_arg_reg, value);
        } else {
            buffer.mov_to_stack(arg_idx << 3, value);
        }
        let out_wrapper_pos = buffer.fixup_position();
        // Out wrapper param goes to first reg that isn't used or stack
        let arg_idx = self.args.len();
        if let Some(&out_wrapper_arg_reg) = arg_registers.get(self.args.len()) {
            buffer.mov_to_reg(out_wrapper_arg_reg, AsmValue::Undecided);
        } else {
            buffer.mov_to_stack(arg_idx << 3, AsmValue::Undecided);
        }
        for (arg_idx, val) in self.args.iter().enumerate().skip(4) {
            buffer.mov_to_stack(arg_idx << 3, AsmValue::from_loc(val));
        }
        for (pos, &reg) in arg_registers.iter().enumerate() {
            if let Some(arg) = self.args.get(pos) {
                buffer.mov_to_reg(reg, AsmValue::from_loc(arg));
            }
        }
        buffer.call(AsmValue::Constant(self.rust_in_wrapper as u64));
        if let Some(orig) = orig {
            buffer.restore_registers(register_store_offset);
            buffer.stack_add(stack_reserve_size);
            unsafe {
                let len = ins_len(orig, JUMP_INS_LEN);
                buffer.copy_instructions(orig, len);
                buffer.jump(AsmValue::Constant(orig as u64 + len as u64));
            }
        } else {
            buffer.stack_add(stack_reserve_size);
            if self.stdcall {
                let stack_arg_count = self.args.iter().filter_map(|x| x.stack_to_opt()).count();
                buffer.ret(stack_arg_count * 8);
            } else {
                buffer.ret(0);
            }
        }
        (out_wrapper_pos, unwind_info.into())
    }

    fn write_standard_hook_out_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        out_wrapper_pos: AsmFixupPos,
        orig: *const u8,
    ) {
        // Just execute orig instructions and jump
        buffer.reset_stack_offset();
        buffer.fixup_to_position(out_wrapper_pos);
        unsafe {
            let len = ins_len(orig, JUMP_INS_LEN);
            buffer.copy_instructions(orig, len);
            // If the jump is included in instruction copy range,
            // it'll be automatically fixed to point to original
            // code as well when the wrapper is written to exec memory.
            // (Have it jump past last copied instruction -- so at start
            // of own instruction -- so rip - 5)
            buffer.buf.extend_from_slice(&[0xe9, 0xfb, 0xff, 0xff, 0xff]);
            buffer.instruction_ranges[0].len += 5;
        }
    }

    fn write_hook_out_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        out_wrapper_pos: AsmFixupPos,
        orig: *const u8,
    ) {
        if self.is_win64_calling_convention() {
            self.write_standard_hook_out_wrapper(buffer, out_wrapper_pos, orig);
            return;
        }
        let pop_size = self.write_out_wrapper_common(buffer, out_wrapper_pos);
        // Push return address manually
        unsafe {
            let len = ins_len(orig, JUMP_INS_LEN);
            let ret_address = buffer.fixup_position();
            buffer.push(AsmValue::Undecided);
            buffer.copy_instructions(orig, len);
            buffer.jump(AsmValue::Constant(orig as u64 + len as u64));
            buffer.fixup_to_position(ret_address);
        }
        buffer.stack_add(pop_size.0);
        buffer.ret(0);
    }

    fn write_import_out_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        out_wrapper_pos: AsmFixupPos,
    ) -> ConstOffset {
        let pop_size = self.write_out_wrapper_common(buffer, out_wrapper_pos);
        let delayed_out = buffer.call_const(!0);
        buffer.stack_add(pop_size.0);
        buffer.ret(0);
        delayed_out
    }

    /// Writes out wrapper up to the point of the actual function call / orig instructions
    fn write_out_wrapper_common(
        &self,
        buffer: &mut AssemblerBuf,
        out_wrapper_pos: AsmFixupPos,
    ) -> StackPopSize {
        buffer.reset_stack_offset();
        buffer.fixup_to_position(out_wrapper_pos);

        let mut stack_args: SmallVec<[_; 8]> = self.args
            .iter()
            .enumerate()
            .filter_map(|(pos, x)| x.stack_to_opt().map(|x| (pos, x)))
            .collect();

        insertion_sort::sort_by_key(&mut stack_args, |&(_, target_pos)| target_pos);

        let stack_args_size = stack_args.last().map(|&(_, x)| x as usize + 1).unwrap_or(0);
        let needs_align = stack_args_size & 1 == 0;
        let align_size = if needs_align { 8 } else { 0 };
        buffer.stack_sub(align_size);

        // Push stack args.
        // Takes possible empty spots into account, so it became kind of complicated.

        for (pos, diff) in stack_args.last()
            .map(|&(pos, _)| (pos, 1))
            .into_iter()
            .chain(stack_args
                   .windows(2)
                   .rev()
                   .map(|tp| (tp[0].0, tp[1].1 - tp[0].1))
            ) {
            if diff > 1 {
                buffer.stack_sub(diff as usize - 1);
            }
            let src = match pos {
                0 => AsmValue::Register(1),
                1 => AsmValue::Register(2),
                2 => AsmValue::Register(8),
                3 => AsmValue::Register(9),
                _ => AsmValue::Stack(pos as i16),
            };
            buffer.push(src);
        }
        for (pos, val) in self.args
                .iter()
                .enumerate()
                .filter_map(|(pos, x)| x.reg_to_opt().map(|x| (pos, x))) {
            // TODO: Can't handle registers going weirdly yet
            let src = match pos {
                0 => AsmValue::Register(1),
                1 => AsmValue::Register(2),
                2 => AsmValue::Register(8),
                3 => AsmValue::Register(9),
                _ => AsmValue::Stack(pos as i16),
            };
            buffer.mov_to_reg(val, src);
        }
        buffer.stack_sub(stack_args.first().map(|x| x.1 as usize).unwrap_or(0x4) * 8);
        if self.stdcall {
            StackPopSize(align_size)
        } else {
            let stack_alloc_size = match stack_args.last() {
                Some(s) => (s.1 as usize + 1) * 8,
                None => 0x20,
            };
            StackPopSize(align_size + stack_alloc_size)
        }
    }
}

// Currently really similar impl as in x86.rs
impl FuncAssembler {
    pub fn new() -> FuncAssembler {
        FuncAssembler {
            buf: AssemblerBuf::new(),
            current_stack: SmallVec::new(),
            preserved_regs: SmallVec::new(),
            arg_num: 0,
            func_offsets: Vec::with_capacity(64),
            offset_pos: 0,
        }
    }

    // Pushes are written at once in `finish_fnwrap`.
    pub fn stack(&mut self, pos: u8) {
        self.current_stack.push((self.arg_num, pos));
        self.arg_num += 1;
    }

    pub fn register(&mut self, reg: u8) {
        if is_preserved_reg(reg) {
            self.buf.push(AsmValue::Register(reg));
            self.preserved_regs.push(reg);
        }
        self.buf.mov_to_reg(reg, AsmValue::for_callee(self.arg_num));
        self.arg_num += 1;
    }

    pub fn new_fnwrap(&mut self) {
        self.buf.reset_stack_offset();
        self.func_offsets.push(self.buf.len());
        self.current_stack.clear();
        self.preserved_regs.clear();
        self.arg_num = 0;
    }

    pub fn finish_fnwrap(&mut self, addr: usize, stdcall: bool) {
        let ptr_size = mem::size_of::<usize>();
        insertion_sort::sort_by_key(&mut self.current_stack, |&(_, x)| x);
        // Align the stack if necessary
        let stack_args_count = self.current_stack.last().map(|&(_, x)| x as usize + 1).unwrap_or(0);
        let needs_align = (stack_args_count + self.preserved_regs.len()) & 1 == 0;
        let align_size = if needs_align { 8 } else { 0 };
        self.buf.stack_sub(align_size);

        for (signature_pos, skipped_args) in
            self.current_stack.windows(2).rev()
            .map(|window| (window[0], window[1]))
            // `skipped_args` is the count of unused stack arg positions in between these
            // two which are used.
            .map(|((_, next_pos), (sign_pos, pos))| (sign_pos, pos - next_pos - 1))
            // Special case for the first stack pos.
            .chain(self.current_stack.first().map(|&(sign, actual)| (sign, actual)))
        {
            self.buf.push(AsmValue::for_callee(signature_pos));
            self.buf.stack_sub(skipped_args as usize * ptr_size);
        }
        self.buf.call(AsmValue::Constant(addr as u64));

        // Pop the frame for stack args (if not stdcall) and the possible alignment filler
        match stdcall {
            true => self.buf.stack_add(align_size),
            false => self.buf.stack_add(stack_args_count * ptr_size + align_size),
        }
        for reg in self.preserved_regs.iter().rev() {
            self.buf.pop(AsmValue::Register(*reg));
        }
        self.buf.ret(0);
        self.buf.write_fixups();
    }

    pub fn write(&mut self, exec_heap: &mut ExecutableHeap) -> *const u8 {
        let data = exec_heap.allocate(self.buf.len());
        unsafe { self.buf.write(data); }
        data
    }

    pub fn next_offset(&mut self) -> usize {
        self.offset_pos += 1;
        self.func_offsets[self.offset_pos - 1]
    }
}

pub struct HookWrapCode {
    buf: AssemblerBuf,
    unwind_info: Vec<u8>,
    import_fixup_offset: usize,
}

impl HookWrapCode {
    /// Allocates a chunk of executable memory and writes all parts of function entry wrapper
    /// there. (Original code, in wrapper, out wrapper, rust objects), in that order.
    ///
    /// Returns pointer to the wrapper, original instruction length and pointer to a pointer
    /// to the wrapper The pointer to pointer is returned so we can use jmp [pointer_to_wrapper]
    /// without having to separately allocate it. Doing a jump that way is ideal since
    /// `jmp [0x12345678] it takes only 6 bytes on x86, while `jmp 0x12345678` takes 12, and
    /// relative jumps don't work with (rather rare use case of) aliasing view patching.
    ///
    /// The original instructions will be copied to memory right before the wrapper,
    /// to be used when patch is disabled.
    #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
    fn write_wrapper(
        &self,
        entry: Option<*const u8>,
        heap: &mut ExecutableHeap,
        unwind_tables: &mut UnwindTables,
    ) -> GeneratedHook {
        let ins_len = |x| { unsafe { ins_len(x, JUMP_INS_LEN) } };

        let entry_orig_ins_len = entry.map(&ins_len).unwrap_or(0);

        let wrapper_len =
            align(self.buf.len(), 8) +
            align(entry_orig_ins_len, 16) +
            8; // + 8 for pointer_to_wrapper
        unsafe {
            let near_range = self.buf.instruction_ranges.iter()
                .filter(|x| !x.orig_base.is_null())
                .map(|x| (x.orig_base, x.orig_base.add(x.len as usize)))
                .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)));
            let (allocator_base, data) = match near_range {
                Some(s) => heap.allocate_near(s, wrapper_len),
                None => {
                    let alloc = heap.any_allocator();
                    (alloc.base(), alloc.allocate(wrapper_len))
                }
            };
            if !self.unwind_info.is_empty() {
                unwind_tables.add_buffered(
                    allocator_base,
                    (data as *const u8, data.add(wrapper_len) as *const u8),
                    &self.unwind_info,
                    heap,
                );
            }

            let entry_orig_ins_ptr = data;
            let wrapper = entry_orig_ins_ptr.add(align(entry_orig_ins_len, 16));
            let wrapper_end = wrapper.add(align(self.buf.len(), 8));
            if let Some(entry) = entry {
                ptr::copy_nonoverlapping(entry, entry_orig_ins_ptr, entry_orig_ins_len);
            }
            self.buf.write(wrapper);
            let entry_pointer_to_wrapper = {
                let ptr = wrapper_end as *mut *const u8;
                *ptr = wrapper;
                ptr
            };
            let entry = GeneratedHook {
                wrapper,
                orig_ins_len: entry_orig_ins_len,
                orig_ins: entry_orig_ins_ptr,
                pointer_to_wrapper: entry_pointer_to_wrapper,
            };
            entry
        }
    }

    pub fn write_import_wrapper(
        &self,
        heap: &mut ExecutableHeap,
        import_fixup: *const u8,
    ) -> GeneratedHook {
        let wrapper_len =
            align(self.buf.len(), 8) +
            8; // + 8 for pointer_to_wrapper
        let data = heap.allocate(wrapper_len);
        unsafe {
            let wrapper = data;
            let wrapper_end = wrapper.add(align(self.buf.len(), 8));
            self.buf.write(wrapper);
            (wrapper.add(self.import_fixup_offset) as *mut usize)
                .write_unaligned(import_fixup as usize);
            let entry_pointer_to_wrapper = {
                let ptr = wrapper_end as *mut *const u8;
                *ptr = wrapper;
                ptr
            };
            let entry = GeneratedHook {
                wrapper,
                orig_ins_len: 0,
                orig_ins: data,
                pointer_to_wrapper: entry_pointer_to_wrapper,
            };
            entry
        }
    }
}

pub struct AssemblerBuf {
    buf: Vec<u8>,
    // Pos in buf, value
    fixups: SmallVec<[(usize, u64); 4]>,
    constants: SmallVec<[(usize, u64); 8]>,
    stack_offset: i32,
    // Will need to copy instructions at most once per hook
    instruction_ranges: [InstructionRange; 1],
}

struct InstructionRange {
    orig_base: *const u8,
    buf_pos: u32,
    len: u32,
}

pub struct AsmFixupPos(usize);

impl AssemblerBuf {
    pub fn new() -> AssemblerBuf {
        AssemblerBuf {
            buf: Vec::with_capacity(128),
            fixups: SmallVec::new(),
            constants: SmallVec::new(),
            stack_offset: 0,
            instruction_ranges: [InstructionRange {
                orig_base: ptr::null(),
                buf_pos: 0,
                len: 0,
            }],
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn reset_stack_offset(&mut self) {
        self.stack_offset = 0;
    }

    pub fn fixup_position(&mut self) -> AsmFixupPos {
        AsmFixupPos(self.fixups.len())
    }

    pub fn fixup_to_position(&mut self, fixup_pos: AsmFixupPos) {
        self.fixups[fixup_pos.0].1 = self.buf.len() as u64;
    }

    pub fn align(&mut self, amount: usize) {
        while self.buf.len() & (amount - 1) != 0 {
            self.buf.push(0xcc);
        }
    }

    unsafe fn copy_instructions(&mut self, source: *const u8, amt: usize) {
        let buf_pos = self.buf.len();
        copy_instructions(source, &mut self.buf, amt);
        let copy_len = self.buf.len() - buf_pos;
        debug_assert!(
            self.instruction_ranges[0].orig_base.is_null(),
            "Second instruction copy is not allowed",
        );
        self.instruction_ranges[0] = InstructionRange {
            orig_base: source,
            buf_pos: buf_pos as u32,
            len: copy_len as u32,
        };
    }

    fn write_fixups(&mut self) -> ConstOffsets {
        let const_offset_begin = self.buf.len() + self.fixups.len() * 8;
        for &(fixup, value) in self.fixups.iter().chain(self.constants.iter()) {
            let offset = self.buf.len() - fixup - 4;
            self.buf.extend_from_slice(&(value as u64).to_le_bytes());
            LE::write_u32(&mut self.buf[fixup..(fixup + 4)], offset as u32);
        }
        self.align(16);
        ConstOffsets(const_offset_begin)
    }

    pub unsafe fn write(&self, out: *mut u8) {
        let diff = out as usize;
        ptr::copy_nonoverlapping(self.buf.as_ptr(), out, self.buf.len());
        for &(fixup, value) in self.fixups.iter() {
            let value_pos = fixup + 4 + LE::read_u32(&self.buf[fixup..(fixup + 4)]) as usize;
            write_unaligned(out.offset(value_pos as isize), value.wrapping_add(diff as u64));
        }
        for range in self.instruction_ranges.iter().filter(|x| !x.orig_base.is_null()) {
            fixup_relative_instructions(
                range.orig_base,
                out.add(range.buf_pos as usize),
                range.len as usize,
            );
        }
    }

    pub fn push(&mut self, val: AsmValue) {
        match val {
            AsmValue::Undecided => {
                self.buf.extend_from_slice(&[0xff, 0x35, 0x00, 0x00, 0x00, 0x00]);
                self.fixups.push((self.buf.len() - 4, 0));
            }
            AsmValue::Constant(val) => {
                self.buf.extend_from_slice(&[0xff, 0x35, 0x00, 0x00, 0x00, 0x00]);
                self.constants.push((self.buf.len() - 4, val));
            }
            AsmValue::Register(reg) => {
                if reg >= 8 {
                    self.buf.push(0x41);
                }
                self.buf.push(0x50 + (reg & 7));
            }
            AsmValue::Stack(pos) => {
                let offset = i32::from(pos * 8) + self.stack_offset + 8;
                match offset {
                    0 => {
                        self.buf.extend_from_slice(&[0xff, 0x34, 0xe4]);
                    }
                    x if x < 0x80 => {
                        self.buf.extend_from_slice(&[0xff, 0x74, 0xe4, x as u8]);
                    }
                    x => {
                        self.buf.extend_from_slice(&[0xff, 0xb4, 0xe4]);
                        self.buf.extend_from_slice(&(x as u32).to_le_bytes());
                    }
                }
            }
        }
        self.stack_offset += 8;
    }

    pub fn pop(&mut self, val: AsmValue) {
        match val {
            AsmValue::Register(reg) => {
                if reg >= 8 {
                    self.buf.push(0x41);
                }
                self.buf.push(0x58 + (reg & 7));
            }
            _ => unimplemented!(),
        }
        self.stack_offset -= 8;
    }

    pub fn store_registers(&mut self, offset: usize) {
        let mut offset = offset;
        for i in 0..16 {
            if i == 4 {
                continue;
            }
            self.mov_to_stack(offset, AsmValue::Register(i));
            offset += 8;
        }
    }

    pub fn restore_registers(&mut self, offset: usize) {
        let mut offset = offset;
        for i in 0..16 {
            if i == 4 {
                continue;
            }
            if offset < 0x80 {
                let bytes = [
                    0x48 | ((i & 8) >> 1),
                    0x8b,
                    0x44 + ((i & 7) << 3),
                    0xe4,
                    offset as u8,
                ];
                self.buf.extend_from_slice(&bytes);
            } else {
                let mut bytes = [
                    0x48 | ((i & 8) >> 1),
                    0x8b,
                    0x84 + ((i & 7) << 3),
                    0xe4,
                    0x00, 0x00, 0x00, 0x00,
                ];
                LE::write_u32(&mut bytes[4..], offset as u32);
                self.buf.extend_from_slice(&bytes);
            }
            offset += 8;
        }
    }

    pub fn mov_to_reg(&mut self, to: u8, from: AsmValue) {
        match from {
            AsmValue::Register(from) => {
                if to != from {
                    let reg_spec_byte = 0x48 + if to >= 8 { 1 } else { 0 } +
                        if from >= 8 { 4 } else { 0 };
                    self.buf.extend_from_slice(
                        &[reg_spec_byte, 0x89, 0xc0 + (from & 7) * 8 + (to & 7)],
                    );
                }
            }
            AsmValue::Stack(from) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.push(reg_spec_byte);
                let offset = (i32::from(from) * 8) + 8 + self.stack_offset;
                match offset {
                    x if x < 0x80 => {
                        self.buf.extend_from_slice(&[0x8b, 0x44 + (to & 7) * 8, 0xe4, x as u8]);
                    }
                    x => {
                        self.buf.extend_from_slice(&[0x8b, 0x84 + (to & 7) * 8, 0xe4]);
                        self.buf.extend_from_slice(&(x as u32).to_le_bytes());
                    }
                }
            }
            AsmValue::Undecided => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.extend_from_slice(
                    &[reg_spec_byte, 0x8b, 0x5 + (to & 7) * 8, 0x00, 0x00, 0x00, 0x00],
                );
                self.fixups.push((self.buf.len() - 4, 0));
            }
            AsmValue::Constant(val) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.extend_from_slice(
                    &[reg_spec_byte, 0x8b, (to & 7) * 8 + 0x5, 0x00, 0x00, 0x00, 0x00],
                );
                self.constants.push((self.buf.len() - 4, val));
            }
        }
    }

    /// Writes move to [rsp + offset] (Dest Offset not affected by self.stack_offset,
    /// from stack offset is).
    /// May clobber rax if necessary.
    pub fn mov_to_stack(&mut self, offset: usize, from: AsmValue) {
        match from {
            AsmValue::Register(from) => {
                if offset < 0x80 {
                    let bytes = [
                        0x48 | ((from & 8) >> 1),
                        0x89,
                        0x44 | ((from & 7) << 3),
                        0x24,
                        offset as u8,
                    ];
                    self.buf.extend_from_slice(&bytes);
                } else {
                    let mut bytes = [
                        0x48 | ((from & 8) >> 1),
                        0x89,
                        0x84 | ((from & 7) << 3),
                        0x24,
                        0x00, 0x00, 0x00, 0x00,
                    ];
                    LE::write_u32(&mut bytes[4..], offset as u32);
                    self.buf.extend_from_slice(&bytes);
                }
            }
            AsmValue::Stack(_) | AsmValue::Undecided | AsmValue::Constant(..) => {
                self.mov_to_reg(0, from);
                self.mov_to_stack(offset, AsmValue::Register(0));
            }
        }
    }

    pub fn stack_add(&mut self, value: usize) {
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.extend_from_slice(&[0x48, 0x83, 0xc4, x as u8]);
            }
            x => {
                self.buf.extend_from_slice(&[0x48, 0x81, 0xc4]);
                self.buf.extend_from_slice(&(x as u32).to_le_bytes());
            }
        }
        self.stack_offset -= value as i32;
    }

    pub fn stack_sub(&mut self, value: usize) {
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.extend_from_slice(&[0x48, 0x83, 0xec, x as u8]);
            }
            x => {
                self.buf.extend_from_slice(&[0x48, 0x81, 0xec]);
                self.buf.extend_from_slice(&(x as u32).to_le_bytes());
            }
        }
        self.stack_offset += value as i32;
    }

    pub fn ret(&mut self, stack_pop: usize) {
        if stack_pop == 0 {
            self.buf.push(0xc3);
        } else {
            self.buf.extend_from_slice(&[0xc2, stack_pop as u8, (stack_pop >> 8) as u8]);
        }
    }

    pub fn jump(&mut self, target: AsmValue) {
        match target {
            AsmValue::Constant(dest) => {
                self.buf.extend_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
                self.constants.push((self.buf.len() - 4, dest));
            }
            AsmValue::Register(dest) => {
                if dest >= 8 {
                    self.buf.push(0x41);
                }
                self.buf.extend_from_slice(&[0xff, 0xe0 + (dest & 7)]);
            }
            _ => unimplemented!(),
        }
    }

    pub fn call(&mut self, target: AsmValue) {
        match target {
            AsmValue::Constant(dest) => {
                self.call_const(dest);
            }
            AsmValue::Register(dest) => {
                if dest >= 8 {
                    self.buf.push(0x41);
                }
                self.buf.extend_from_slice(&[0xff, 0xd0 + (dest & 7)]);
            }
            _ => unimplemented!(),
        }
    }

    fn call_const(&mut self, val: u64) -> ConstOffset {
        self.buf.extend_from_slice(&[0xff, 0x15, 0x00, 0x00, 0x00, 0x00]);
        self.constants.push((self.buf.len() - 4, val));
        ConstOffset(self.constants.len() - 1)
    }
}

/// Does not fix rip-relative instructions, caller will have to do it afterwards.
unsafe fn copy_instructions(
    src: *const u8,
    dst: &mut Vec<u8>,
    min_length: usize,
) {
    let mut left = min_length;
    let mut copy_len = 0usize;
    for (opcode, _) in lde::X64.iter(slice::from_raw_parts(src, min_length + 32), 0) {
        if left == 0 {
            break;
        }
        // Special case long jumps written by this library (jmp [rip])
        let ins_len = if opcode[..] == [0xff, 0x25, 0x00, 0x00, 0x00, 0x00] {
            JUMP_INS_LEN
        } else {
            opcode.len()
        };
        copy_len += ins_len;
        left = match left.checked_sub(ins_len) {
            Some(s) => s,
            None => break,
        };
    }
    let slice = slice::from_raw_parts(src, copy_len);
    dst.extend_from_slice(slice);
}

pub unsafe fn ins_len(ins: *const u8, min_length: usize) -> usize {
    let mut sum = 0;
    for (opcode, _) in lde::X64.iter(slice::from_raw_parts(ins, min_length + 32), 0) {
        if sum >= min_length {
            break;
        }
        // Special case long jumps written by this library (jmp [rip])
        if opcode[..] == [0xff, 0x25, 0x00, 0x00, 0x00, 0x00] {
            sum += JUMP_INS_LEN;
        } else {
            sum += opcode.len();
        }
    }
    sum
}

unsafe fn fixup_relative_instructions(
    orig_base: *const u8,
    new_base: *mut u8,
    len: usize,
) {
    let offset = (new_base as usize).wrapping_sub(orig_base as usize) as u32;
    let mut pos = 0;
    while pos < len {
        let mut ins_bytes = new_base.add(pos);
        // Skip past prefixes
        while is_prefix(*ins_bytes) {
            ins_bytes = ins_bytes.add(1);
            pos += 1;
        }
        let ins_len = ins_len(ins_bytes as *const u8, 1);
        let bit_pair_index = if *ins_bytes == 0xf {
            0x100 + *ins_bytes.add(1) as usize
        } else {
            *ins_bytes as usize
        };
        let ins_param = ins_bytes.add(1 + (bit_pair_index >> 8));
        let index = bit_pair_index >> 2;
        let shift = (bit_pair_index & 3) << 1;
        let info = (INSTRUCTION_INFO[index] >> shift) & 3;
        if info != 0 {
            if info == 1 {
                // ModRM byte, rip-relative if 0xc7 == 5
                let rm = *ins_param;
                if rm & 0xc7 == 5 {
                    let rel = ins_param.add(1) as *mut u32;
                    let old_val = rel.read_unaligned();
                    // Fixup only if not pointing to the copied code itself
                    if pos.wrapping_add(ins_len)
                        .wrapping_add(old_val as i32 as isize as usize) >= len
                    {
                        rel.write_unaligned(old_val.wrapping_sub(offset));
                    }
                }
            } else {
                // Relative jump / call
                // Can't be prefix since they're skipped over at is_prefix
                let rel = ins_param as *mut u32;
                rel.write_unaligned(rel.read_unaligned().wrapping_sub(offset));
            }
        }
        pos += ins_len;
    }
}

fn is_prefix(byte: u8) -> bool {
    let index = byte as usize >> 2;
    let shift = (byte & 3) << 1;
    (INSTRUCTION_INFO[index] >> shift) & 3 == 3
}

/// 2 bits per instruction:
/// 00 = Nothing
/// 01 = Has modrm byte
/// 10 = Relative u32 jump
/// 11 = Prefix
static INSTRUCTION_INFO: [u8; 0x80] = [
    //         03 02 01 00    07 06 05 04    0b 0a 09 08    0f 0e 0d 0c
    /* 00 */ 0b01_01_01_01, 0b00_00_00_00, 0b01_01_01_01, 0b00_00_00_00,
    /* 10 */ 0b01_01_01_01, 0b00_00_00_00, 0b01_01_01_01, 0b00_00_00_00,
    /* 20 */ 0b01_01_01_01, 0b00_00_00_00, 0b01_01_01_01, 0b00_00_00_00,
    /* 30 */ 0b01_01_01_01, 0b00_00_00_00, 0b01_01_01_01, 0b00_00_00_00,
    /* 40 */ 0b11_11_11_11, 0b11_11_11_11, 0b11_11_11_11, 0b11_11_11_11,
    /* 50 */ 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00,
    /* 60 */ 0b01_00_00_00, 0b11_11_11_11, 0b01_00_01_00, 0b00_00_00_00,
    /* 70 */ 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00,
    /* 80 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 90 */ 0b00_00_00_00, 0b00_00_00_00, 0b11_00_00_00, 0b00_00_00_00,
    /* a0 */ 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00,
    /* b0 */ 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00,
    /* c0 */ 0b00_00_01_01, 0b01_01_00_00, 0b00_00_00_00, 0b00_00_00_00,
    /* d0 */ 0b01_01_01_01, 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00,
    /* e0 */ 0b00_00_00_00, 0b00_00_00_00, 0b00_00_10_10, 0b00_00_00_00,
    /* f0 */ 0b11_11_00_00, 0b01_01_00_00, 0b00_00_00_00, 0b01_01_00_00,
    //            03 02 01 00    07 06 05 04    0b 0a 09 08    0f 0e 0d 0c
    /* 0f 00 */ 0b00_00_00_00, 0b00_00_00_00, 0b00_00_00_00, 0b00_00_01_00,
    /* 0f 10 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f 20 */ 0b00_00_00_00, 0b00_00_00_00, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f 30 */ 0b00_00_00_00, 0b00_00_00_00, 0b01_01_01_01, 0b00_00_00_00,
    /* 0f 40 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f 50 */ 0b01_01_01_00, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f 60 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f 70 */ 0b00_00_00_01, 0b00_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f 80 */ 0b10_10_10_10, 0b10_10_10_10, 0b10_10_10_10, 0b10_10_10_10,
    /* 0f 90 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f a0 */ 0b01_00_00_00, 0b00_00_01_01, 0b01_00_00_00, 0b01_00_01_01,
    /* 0f b0 */ 0b01_00_01_01, 0b01_01_00_00, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f c0 */ 0b01_01_01_01, 0b01_01_01_01, 0b00_00_00_00, 0b00_00_00_00,
    /* 0f d0 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f e0 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
    /* 0f f0 */ 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01, 0b01_01_01_01,
];
