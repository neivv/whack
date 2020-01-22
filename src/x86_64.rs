use std::mem;
use std::ptr;
use std::slice;

use lde;
use byteorder::{ByteOrder, LE};
use smallvec::SmallVec;

use helpers::*;
use insertion_sort;
use OrigFuncCallback;
pub use win_common::*;

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

#[repr(C)]
pub struct InlineCallCtx {
    stack_copy_size: usize,
    regs: [usize; 8],
}

impl InlineCallCtx {
    pub fn init_stack_copy_size(&mut self) {
        let rbp = self.regs[5];
        let rsp = self.regs[4];
        let val = rbp.wrapping_sub(rsp).wrapping_add(0x40);
        self.stack_copy_size = if val > 0x20 && val < 0x2000 {
            val
        } else {
            0x200
        };
    }
}

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

    pub fn generate_wrapper_code(&self, orig: OrigFuncCallback) -> HookWrapCode {
        let mut buffer = AssemblerBuf::new();

        let out_wrapper_pos = self.write_in_wrapper(&mut buffer, orig);
        let import_fixup_offset = match orig {
            OrigFuncCallback::Overwritten(orig) => {
                self.write_out_wrapper(&mut buffer, out_wrapper_pos, Some(orig))
            }
            OrigFuncCallback::ImportHook => {
                self.write_out_wrapper(&mut buffer, out_wrapper_pos, None)
            }
            OrigFuncCallback::None |
                OrigFuncCallback::Hook(_) |
                OrigFuncCallback::Inline(..) =>
            {
                None
            }
        };
        buffer.align(16);
        let const_offsets = buffer.write_fixups();

        HookWrapCode {
            buf: buffer,
            import_fixup_offset: import_fixup_offset.map(|x| const_offsets.to_offset(x))
                .unwrap_or(0),
            exit_wrapper_offset: 0,
        }
    }

    pub fn generate_wrapper_code_inline(
        &self,
        _entry: *const u8,
        _exit: *const u8,
        _parent: *const u8,
    ) -> HookWrapCode {
        unimplemented!()
    }

    fn write_in_wrapper(&self, buffer: &mut AssemblerBuf, orig: OrigFuncCallback) -> AsmFixupPos {
        let needs_align = {
            let pushad_size = if let OrigFuncCallback::Hook(_) = orig { 15 } else { 0 };
            let stack_args = ::std::cmp::max(0, self.args.len() as i32 + 2 - 4);
            (pushad_size + stack_args) & 1 == 0
        };
        let align_size = if needs_align { 8 } else { 0 };
        buffer.stack_sub(align_size);

        if let OrigFuncCallback::Hook(_) = orig {
            buffer.pushad();
        }
        match self.args.len() {
            0 => buffer.mov(AsmValue::Register(2), AsmValue::Constant(self.target as u64)),
            1 => buffer.mov(AsmValue::Register(8), AsmValue::Constant(self.target as u64)),
            2 => buffer.mov(AsmValue::Register(9), AsmValue::Constant(self.target as u64)),
            _ => buffer.push(AsmValue::Constant(self.target as u64)),
        };
        let out_wrapper_pos = buffer.fixup_position();
        match self.args.len() {
            0 => buffer.mov(AsmValue::Register(1), AsmValue::Undecided),
            1 => buffer.mov(AsmValue::Register(2), AsmValue::Undecided),
            2 => buffer.mov(AsmValue::Register(8), AsmValue::Undecided),
            3 => buffer.mov(AsmValue::Register(9), AsmValue::Undecided),
            _ => buffer.push(AsmValue::Undecided),
        }
        for val in self.args.iter().skip(4).rev() {
            buffer.push(AsmValue::from_loc(val));
        }
        // A scope to satisfy borrowck
        {
            let mut move_to_reg = |pos, reg| {
                if let Some(arg) = self.args.get(pos) {
                    buffer.mov(AsmValue::Register(reg), AsmValue::from_loc(arg));
                }
            };
            move_to_reg(0, 1);
            move_to_reg(1, 2);
            move_to_reg(2, 8);
            move_to_reg(3, 9);
        }
        buffer.stack_sub(0x20);
        buffer.call(AsmValue::Constant(self.rust_in_wrapper as u64));
        buffer.stack_add(::std::cmp::max((self.args.len() + 2) * 8, 0x20));
        if let OrigFuncCallback::Hook(orig) = orig {
            buffer.popad();
            buffer.stack_add(align_size);
            unsafe {
                let len = ins_len(orig, JUMP_INS_LEN);
                buffer.copy_instructions(orig, len);
                buffer.jump(AsmValue::Constant(orig as u64 + len as u64));
            }
        } else {
            buffer.stack_add(align_size);
            if self.stdcall {
                let stack_arg_count = self.args.iter().filter_map(|x| x.stack_to_opt()).count();
                buffer.ret(stack_arg_count * 8);
            } else {
                buffer.ret(0);
            }
        }
        out_wrapper_pos
    }

    // Returns offset to fix delayed out address
    fn write_out_wrapper(&self,
                         buffer: &mut AssemblerBuf,
                         out_wrapper_pos: AsmFixupPos,
                         orig: Option<*const u8>,
                        ) -> Option<ConstOffset> {
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
            buffer.mov(AsmValue::Register(val), src);
        }
        buffer.stack_sub(stack_args.first().map(|x| x.1 as usize).unwrap_or(0x4) * 8);
        let delayed_out = if let Some(orig) = orig {
            // Push return address manually
            unsafe {
                let len = ins_len(orig, 6 + 8);
                let ret_address = buffer.fixup_position();
                buffer.push(AsmValue::Undecided);
                buffer.copy_instructions(orig, len);
                buffer.jump(AsmValue::Constant(orig as u64 + len as u64));
                buffer.fixup_to_position(ret_address);
            }
            None
        } else {
            Some(buffer.call_const(!0))
        };
        buffer.stack_add(align_size + if self.stdcall { 0 } else {
            stack_args.last().map(|x| (x.1 + 1) as usize * 8).unwrap_or(0x20)
        });
        buffer.ret(0);
        delayed_out
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
        self.buf.mov(AsmValue::Register(reg), AsmValue::for_callee(self.arg_num));
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
    import_fixup_offset: usize,
    exit_wrapper_offset: usize,
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
    /// The original instructions will be copied to memory right before the wrapper,
    /// to be used when patch is disabled.
    #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
    pub fn write_wrapper(
        &self,
        entry: Option<*const u8>,
        exit: Option<*const u8>,
        _inline_parent_entry: Option<*const u8>,
        heap: &mut ExecutableHeap,
        import_fixup: Option<*const u8>,
    ) -> (::GeneratedHook, Option<::GeneratedHook>, Option<::GeneratedHook>) {
        let ins_len = |x| { unsafe { ins_len(x, JUMP_INS_LEN) } };

        let entry_orig_ins_len = entry.map(&ins_len).unwrap_or(0);
        let exit_orig_ins_len = exit.map(&ins_len).unwrap_or(0);

        let wrapper_len =
            align(self.buf.len(), 8) +
            align(entry_orig_ins_len, 8) +
            align(exit_orig_ins_len, 8) + 16;
        let data = heap.allocate(wrapper_len);
        let entry_orig_ins_ptr = data;
        let exit_orig_ins_ptr = unsafe {
            entry_orig_ins_ptr.offset(align(entry_orig_ins_len, 8) as isize)
        };
        let wrapper = unsafe {
            exit_orig_ins_ptr.offset(align(exit_orig_ins_len, 8) as isize)
        };
        let wrapper_end = unsafe {
            wrapper.offset(align(self.buf.len(), 8) as isize)
        };
        if let Some(entry) = entry {
            unsafe { ptr::copy_nonoverlapping(entry, entry_orig_ins_ptr, entry_orig_ins_len) };
        }
        if let Some(exit) = exit {
            unsafe { ptr::copy_nonoverlapping(exit, exit_orig_ins_ptr, exit_orig_ins_len) };
        }
        let exit_wrapper = unsafe { wrapper.offset(self.exit_wrapper_offset as isize) };
        unsafe { self.buf.write(wrapper); }
        if let Some(fixup) = import_fixup {
            unsafe {
                let offset = self.import_fixup_offset as isize;
                write_unaligned(wrapper.offset(offset), fixup as usize);
            }
        }
        let entry_pointer_to_wrapper = unsafe {
            let ptr = wrapper_end as *mut *const u8;
            *ptr = wrapper;
            ptr
        };
        let exit_pointer_to_wrapper = unsafe {
            let ptr = wrapper_end.offset(8) as *mut *const u8;
            *ptr = exit_wrapper;
            ptr
        };
        let entry = ::GeneratedHook {
            wrapper,
            orig_ins_len: entry_orig_ins_len,
            orig_ins: entry_orig_ins_ptr,
            pointer_to_wrapper: entry_pointer_to_wrapper,
        };
        let exit = exit.map(|_| ::GeneratedHook {
            wrapper: exit_wrapper,
            orig_ins_len: exit_orig_ins_len,
            orig_ins: exit_orig_ins_ptr,
            pointer_to_wrapper: exit_pointer_to_wrapper,
        });
        (entry, exit, None)
    }
}

pub struct AssemblerBuf {
    buf: Vec<u8>,
    // Pos in buf, value
    fixups: SmallVec<[(usize, u64); 4]>,
    constants: SmallVec<[(usize, u64); 8]>,
    stack_offset: i32,
}

pub struct AsmFixupPos(usize);

impl AssemblerBuf {
    pub fn new() -> AssemblerBuf {
        AssemblerBuf {
            buf: Vec::with_capacity(128),
            fixups: SmallVec::new(),
            constants: SmallVec::new(),
            stack_offset: 0,
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
        while self.buf.len() % amount != 0 {
            self.buf.push(0xcc);
        }
    }

    pub unsafe fn copy_instructions(&mut self, source: *const u8, amt: usize) {
        copy_instructions(source, &mut self.buf, amt);
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

    pub fn pushad(&mut self) {
        for x in 0x50..0x55 {
            self.buf.push(x);
        }
        // Skip rsp
        for x in 0x56..0x58 {
            self.buf.push(x);
        }
        for x in 0x50..0x58 {
            self.buf.extend_from_slice(&[0x41, x]);
        }
        self.stack_offset += 15 * 8;
    }

    pub fn popad(&mut self) {
        for x in (0x58..0x60).rev() {
            self.buf.extend_from_slice(&[0x41, x]);
        }
        for x in (0x5e..0x60).rev() {
            self.buf.push(x);
        }
        // Skip rsp
        for x in (0x58..0x5d).rev() {
            self.buf.push(x);
        }
        self.stack_offset -= 15 * 8;
    }

    pub fn mov(&mut self, to: AsmValue, from: AsmValue) {
        match (to, from) {
            (AsmValue::Register(to), AsmValue::Register(from)) => {
                if to != from {
                    let reg_spec_byte = 0x48 + if to >= 8 { 1 } else { 0 } +
                        if from >= 8 { 4 } else { 0 };
                    self.buf.extend_from_slice(
                        &[reg_spec_byte, 0x89, 0xc0 + (from & 7) * 8 + (to & 7)],
                    );
                }
            }
            (AsmValue::Register(to), AsmValue::Stack(from)) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.push(reg_spec_byte);
                let offset = (i32::from(from) * 8) + 8 + self.stack_offset;
                match offset {
                    0 => {
                        self.buf.extend_from_slice(&[0x8b, 0x4 + (to & 7) * 8, 0xe4]);
                    }
                    x if x < 0x80 => {
                        self.buf.extend_from_slice(&[0x8b, 0x44 + (to & 7) * 8, 0xe4, x as u8]);
                    }
                    x => {
                        self.buf.extend_from_slice(&[0x8b, 0x84 + (to & 7) * 8, 0xe4]);
                        self.buf.extend_from_slice(&(x as u32).to_le_bytes());
                    }
                }
            }
            (AsmValue::Register(to), AsmValue::Undecided) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.extend_from_slice(
                    &[reg_spec_byte, 0x8b, 0x5 + (to & 7) * 8, 0x00, 0x00, 0x00, 0x00],
                );
                self.fixups.push((self.buf.len() - 4, 0));
            }
            (AsmValue::Register(to), AsmValue::Constant(val)) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.extend_from_slice(
                    &[reg_spec_byte, 0x8b, (to & 7) * 8 + 0x5, 0x00, 0x00, 0x00, 0x00],
                );
                self.constants.push((self.buf.len() - 4, val));
            }
            (_, _) => unimplemented!(),
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

    fn call_const(&mut self, val: u64) -> ConstOffset{
        self.buf.extend_from_slice(&[0xff, 0x15, 0x00, 0x00, 0x00, 0x00]);
        self.constants.push((self.buf.len() - 4, val));
        ConstOffset(self.constants.len() - 1)
    }
}

// Dst_base is the address at which the code is *imagined* to be at, so it won't matter if
// the vector is reallocated.
//
// (The rest of the code doesn't actually work with that yet though)
unsafe fn copy_instructions(
    src: *const u8,
    dst: &mut Vec<u8>,
    min_length: usize,
) {
    let mut len = min_length as isize;
    let mut pos = src;
    for (opcode, _) in lde::X64.iter(slice::from_raw_parts(src, min_length + 32), 0) {
        if len <= 0 {
            return;
        }
        let ins_len = opcode.len() as isize;
        if opcode.len() == 7 && &opcode[..3] == [0x48, 0xff, 0x25] {
            // Jmp [rip + offset],
            // replace with jmp [rip + 7]; db xxxx_xxxx_xxxx_xxxx
            dst.extend_from_slice(&[0x48, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
            let offset = *(pos.add(3) as *const i32);
            let dest = *(pos.offset(offset as isize + 7) as *const u64);
            dst.extend_from_slice(&(dest as u64).to_le_bytes());
        } else if opcode[0] == 0xe9 {
            // Long jump
            // replace with jmp [rip + 7]; db xxxx_xxxx_xxxx_xxxx
            dst.extend_from_slice(&[0x48, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
            let offset = *(pos.add(1) as *const i32);
            let dest = ((pos as isize + 5).wrapping_add(offset as isize)) as u64;
            dst.extend_from_slice(&(dest as u64).to_le_bytes());
        } else {
            let slice = slice::from_raw_parts(opcode.as_ptr(), ins_len as usize);
            dst.extend_from_slice(slice);
        }
        pos = pos.offset(ins_len);
        len -= ins_len;
    }
    if len != 0 {
        panic!("Could not disassemble {:x}", src as usize);
    }
}

pub unsafe fn ins_len(ins: *const u8, min_length: usize) -> usize {
    let mut sum = 0;
    for (opcode, _) in lde::X64.iter(slice::from_raw_parts(ins, min_length + 32), 0) {
        if sum >= min_length {
            break;
        }
        sum += opcode.len();
    }
    sum
}
