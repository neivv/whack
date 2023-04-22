#![cfg_attr(feature = "cargo-clippy", allow(fn_to_numeric_cast))]

use std::cell::RefCell;
use std::mem;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};

use lde;
use byteorder::{ByteOrder, LE};
use smallvec::SmallVec;

use crate::helpers::*;
use crate::insertion_sort;
use crate::{OrigFuncCallback, GeneratedHook};

pub use crate::win_common::*;

// hack for rustc const eval false errors
fn cast_fnptr_usize(x: usize) -> u32 {
    x as u32
}

const JUMP_INS_LEN: usize = 6;
#[inline]
pub unsafe fn write_jump_to_ptr(from: *mut u8, to_ptr: *const *const u8) {
    // jmp [to_ptr]
    // We want to use a position-independent jump so it works with aliasing view patching.
    *from = 0xff;
    *from.add(1) = 0x25;
    (from.add(2) as *mut u32).write_unaligned(to_ptr as u32);
}

#[repr(C)]
pub struct InlineCallCtx {
    stack_copy_size: usize,
    regs: [usize; 8],
}

impl InlineCallCtx {
    pub fn init_stack_copy_size(&mut self) {
        let ebp = self.regs[2];
        let esp = self.regs[3];
        let val = ebp.wrapping_sub(esp).wrapping_add(8) & !0xf;
        self.stack_copy_size = if val > 0x20 && val < 0x2000 {
            val
        } else {
            0x200
        };
    }
}

thread_local! {
    static TLS: RefCell<Vec<Vec<*const InlineCallCtx>>> = RefCell::new(Vec::new());
}

fn new_inline_tls_id() -> usize {
    static TLS_IDS: AtomicUsize = AtomicUsize::new(0);
    TLS_IDS.fetch_add(1, Ordering::SeqCst)
}

extern fn get_inline_tls(id: usize) -> *const InlineCallCtx {
    TLS.with(|x| {
        let val = x.borrow();
        let ptr = val[id].last().cloned();
        ptr.unwrap_or_else(|| ptr::null())
    })
}

extern fn set_inline_tls(ctx: *const InlineCallCtx, id: usize) {
    TLS.with(|x| {
        let mut val = x.borrow_mut();
        while val.len() <= id {
            val.push(Vec::new());
        }
        (val)[id].push(ctx);
    });
}

extern fn inline_tls_push_disable(id: usize) {
    set_inline_tls(ptr::null(), id);
}

extern fn inline_tls_pop_enabled(id: usize) {
    TLS.with(|x| {
        let mut val = x.borrow_mut();
        let prev = val[id].pop().unwrap();
        assert!(!prev.is_null());
    });
}

extern fn inline_tls_pop_disable(id: usize) {
    TLS.with(|x| {
        let mut val = x.borrow_mut();
        let prev = val[id].pop().unwrap();
        assert!(prev.is_null());
    });
}

fn is_preserved_reg(reg: u8) -> bool {
    match reg {
        0 | 1 | 2 => false,
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
/// Defines arguments for hooks where the arguments weren't defined statically.
pub enum Location {
    /// Register, 0 = eax/rax, 1 = ecx/rcx, etc.
    Register(u8),
    /// Offset from the stack pointer. Stack(0) would be return address on hooks at function
    /// entry, Stack(0) would be the first argument.
    Stack(i16),
    /// Alternative to Stack, uses offset instead of arg id.
    Esp(i16),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AsmValue {
    Register(u8),
    Stack(i16),
    EaxPtr(i16),
    Undecided,
    Constant(u32),
}

impl Location {
    fn reg_to_opt(&self) -> Option<u8> {
        match *self {
            Location::Register(x) => Some(x),
            Location::Stack(_) => None,
            Location::Esp(_) => None,
        }
    }

    fn stack_to_opt(&self) -> Option<i16> {
        match *self {
            Location::Register(_) => None,
            Location::Stack(x) => Some(x),
            Location::Esp(x) => Some((x - 4) / 4),
        }
    }
}

impl AsmValue {
    fn from_loc(loc: &Location) -> AsmValue {
        match *loc {
            Location::Register(x) => AsmValue::Register(x),
            Location::Stack(x) => AsmValue::Stack(x),
            Location::Esp(x) => AsmValue::Stack((x - 4) / 4),
        }
    }
}

struct InlineTlsValues {
    tls_id: u32,
    set_inline_tls: u32,
    inline_tls_pop_enabled: u32,
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

    /// Returns the buffer and possible offset for fixup original ptr for import hooks.
    pub fn generate_wrapper_code(&self, orig: OrigFuncCallback) -> HookWrapCode {
        let mut buffer = AssemblerBuf::new();
        let dummy = InlineTlsValues {
            tls_id: 0,
            set_inline_tls: 0,
            inline_tls_pop_enabled: 0,
        };
        let out_wrapper_pos = self.write_in_wrapper(&mut buffer, &dummy, orig);
        // Only write out wrappers when needed
        let delayed_out = match orig {
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
                !0
            }
        };
        HookWrapCode {
            buf: buffer,
            import_fixup_offset: delayed_out,
            exit_wrapper_offset: 0,
            parent_hook_offset: 0,
        }
    }

    /// Returns the buffer and possible offset for fixup original ptr for import hooks.
    ///
    /// For inline hooks. Separate so that it won't get complied in if inline hooks
    /// aren't used.
    pub fn generate_wrapper_code_inline(
        &self,
        entry: *const u8,
        exit: *const u8,
        parent: *const u8,
    ) -> HookWrapCode {
        let mut buffer = AssemblerBuf::new();
        let orig = OrigFuncCallback::Inline(entry, exit, parent);
        let tls_values = InlineTlsValues {
            tls_id: new_inline_tls_id() as u32,
            set_inline_tls: cast_fnptr_usize(set_inline_tls as usize),
            inline_tls_pop_enabled: cast_fnptr_usize(inline_tls_pop_enabled as usize),
        };
        let out_wrapper_pos = self.write_in_wrapper(&mut buffer, &tls_values, orig);
        let mut parent_hook_offset = 0;

        self.write_inline_out_wrapper(&mut buffer, out_wrapper_pos, entry);
        let exit_wrapper_offset = buffer.len();
        self.write_inline_exit_hook(&mut buffer, tls_values.tls_id, exit);
        if !parent.is_null() {
            parent_hook_offset = buffer.len();
            self.write_inline_parent_hook(&mut buffer, tls_values.tls_id, parent);
        }
        HookWrapCode {
            buf: buffer,
            import_fixup_offset: !0,
            exit_wrapper_offset,
            parent_hook_offset,
        }
    }

    // Returns fixup pos for out_wrapper's address
    fn write_in_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        // Dummy values if no inline
        inline_tls: &InlineTlsValues,
        orig: OrigFuncCallback,
    ) -> AsmFixupPos {
        match orig {
            OrigFuncCallback::Hook(_) => {
                buffer.pushad();
            }
            OrigFuncCallback::Inline(..) => {
                buffer.pushad();
                // It'll also alloc space for InlineCallCtx::stack_copy_size with this push
                buffer.push(AsmValue::Constant(inline_tls.tls_id));
                buffer.push(AsmValue::Register(4));
                buffer.call(AsmValue::Constant(inline_tls.set_inline_tls));
                buffer.stack_add(8);
                buffer.popad();
                buffer.stack_sub(0x28);
            }
            _ => (),
        }
        buffer.push(AsmValue::Constant(self.target as u32));
        let out_wrapper_pos = buffer.fixup_position();
        buffer.push(AsmValue::Undecided);
        for val in self.args.iter().rev() {
            buffer.push(AsmValue::from_loc(val));
        }
        buffer.call(AsmValue::Constant(self.rust_in_wrapper as u32));
        if let OrigFuncCallback::Inline(..) = orig {
            buffer.stack_add((self.args.len() + 3) * 4);
        } else {
            buffer.stack_add((self.args.len() + 2) * 4);
        }
        match orig {
            OrigFuncCallback::Hook(orig) => {
                buffer.popad();
                unsafe {
                    let len = copy_instruction_length(orig, JUMP_INS_LEN);
                    buffer.copy_instructions(orig, len);
                    buffer.jump(AsmValue::Constant(orig as u32 + len as u32));
                }
            }
            OrigFuncCallback::Inline(_, exit, _) => {
                buffer.push(AsmValue::Constant(inline_tls.tls_id));
                buffer.call(
                    AsmValue::Constant(inline_tls.inline_tls_pop_enabled)
                );
                buffer.stack_add(8);
                buffer.popad();
                unsafe {
                    let len = copy_instruction_length(exit, JUMP_INS_LEN);
                    buffer.copy_instructions(exit, len);
                    buffer.jump(AsmValue::Constant(exit as u32 + len as u32));
                }
            }
            _ => {
                if self.stdcall {
                    let stack_arg_count = self.args.iter()
                        .filter_map(|x| x.stack_to_opt())
                        .count();
                    buffer.ret(stack_arg_count * 4);
                } else {
                    buffer.ret(0);
                }
            }
        }
        out_wrapper_pos
    }

    fn write_inline_out_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        out_wrapper_pos: AsmFixupPos,
        entry: *const u8,
    ) {
        buffer.reset_stack_offset();
        buffer.fixup_to_position(out_wrapper_pos);
        buffer.push(AsmValue::Register(3));
        buffer.push(AsmValue::Register(5));
        buffer.push(AsmValue::Register(6));
        buffer.push(AsmValue::Register(7));
        buffer.mov(AsmValue::Register(0), AsmValue::Stack(0));
        buffer.mov(AsmValue::Register(1), AsmValue::EaxPtr(0));
        buffer.stack_sub_reg(1);
        let pushad_offset = 0x4;
        buffer.mov(AsmValue::Register(6), AsmValue::EaxPtr(pushad_offset  + 0xc));
        buffer.mov(AsmValue::Register(7), AsmValue::Register(4));
        buffer.buf.extend_from_slice(&[0xf3, 0xa4]);

        let mut stack_args: SmallVec<[_; 8]> = self.args
            .iter()
            .enumerate()
            .filter_map(|(pos, x)| x.stack_to_opt().map(|x| (pos, x)))
            .collect();

        insertion_sort::sort_by_key(&mut stack_args, |&(_, target_pos)| target_pos);
        let stack_off = (1u8..8).filter(|&x| x != 4)
            .find(|&reg| !self.args.iter().filter_map(|x| x.reg_to_opt()).any(|x| x == reg))
            .expect("No free reg");
        let second_scratch = match stack_off {
            2 => 1,
            _ => 2,
        };
        buffer.mov(AsmValue::Register(stack_off), AsmValue::EaxPtr(0));
        for (in_pos, out_pos) in stack_args {
            buffer.mov_reg_offset(
                AsmValue::Register(second_scratch),
                AsmValue::Stack(in_pos as i16 + 1),
                stack_off,
            );
            // Mov [esp + out_pos * 4], edx
            buffer.buf.extend_from_slice(
                &[0x89, 0x44 + second_scratch * 8, 0xe4, out_pos as u8 * 4 + 4]
            );
        }

        for reg in (1u8..8).filter(|&x| x != 4 && x != stack_off) {
            buffer.mov(
                AsmValue::Register(reg),
                AsmValue::EaxPtr(pushad_offset + 0x1c - i16::from(reg) * 4),
            );
        }
        let reg_args = self.args
            .iter()
            .enumerate()
            .filter_map(|(pos, x)| x.reg_to_opt().map(|x| (pos, x)));
        buffer.push(AsmValue::Register(0));
        for (pos, reg) in reg_args {
            buffer.mov_reg_offset(
                AsmValue::Register(reg),
                AsmValue::Stack(pos as i16 + 1),
                stack_off
            );
        }
        // Restore the stack_off register, can't use EaxPtr if it was overwritten already.
        // mov stack_off, [stack_off + offset]
        buffer.pop(AsmValue::Register(stack_off));
        buffer.buf.extend_from_slice(
            &[0x8b, 0x40 + 9 * stack_off, pushad_offset as u8 + 0x1c - stack_off * 4]
        );
        if !self.args.iter().any(|&x| x == Location::Register(0)) {
            buffer.mov(AsmValue::Register(0), AsmValue::EaxPtr(pushad_offset + 0x1c));
        }
        unsafe {
            let len = copy_instruction_length(entry, JUMP_INS_LEN);
            buffer.copy_instructions(entry, len);
            buffer.jump(AsmValue::Constant(entry as u32 + len as u32));
        }
    }

    fn write_inline_exit_hook(
        &self,
        buffer: &mut AssemblerBuf,
        tls_id: u32,
        exit: *const u8,
    ) {
        buffer.reset_stack_offset();
        buffer.pushfd();
        buffer.push(AsmValue::Register(0));
        buffer.push(AsmValue::Register(1));
        buffer.push(AsmValue::Register(2));
        buffer.push(AsmValue::Constant(tls_id));
        buffer.call(AsmValue::Constant(cast_fnptr_usize(get_inline_tls as usize)));
        buffer.pop(AsmValue::Register(1));
        // Doing rest like this due to the jump
        buffer.buf.extend_from_slice(&[
            0x85, 0xc0,
            0x74, 0x0c,
            0x8b, 0x08,
            0x83, 0xc4, 0x10,
            0x01, 0xcc,
            0x5f,
            0x5e,
            0x5d,
            0x5b,
            0xc3,
            // was_not_returing_from_orig
            0x5a,
            0x59,
            0x58,
            0x9d,
        ]);
        unsafe {
            let len = copy_instruction_length(exit, JUMP_INS_LEN);
            buffer.copy_instructions(exit, len);
            buffer.jump(AsmValue::Constant(exit as u32 + len as u32));
        }
    }

    fn write_inline_parent_hook(
        &self,
        buffer: &mut AssemblerBuf,
        tls_id: u32,
        parent: *const u8,
    ) {
        buffer.reset_stack_offset();
        // Hooks the parent entry, calling pushing a "disable" to TLS stack on entry
        // and popping on exit.
        buffer.pushad();
        buffer.push(AsmValue::Constant(tls_id));
        buffer.call(AsmValue::Constant(cast_fnptr_usize(inline_tls_push_disable as usize)));
        buffer.pop(AsmValue::Register(0));
        buffer.popad();
        for i in (0..12).rev() {
            buffer.push(AsmValue::Stack(i))
        }
        let return_addr = buffer.fixup_position();
        buffer.push(AsmValue::Undecided);
        unsafe {
            let len = copy_instruction_length(parent, JUMP_INS_LEN);
            buffer.copy_instructions(parent, len);
            buffer.jump(AsmValue::Constant(parent as u32 + len as u32));
        }
        buffer.fixup_to_position(return_addr);
        buffer.pushad();
        buffer.push(AsmValue::Constant(tls_id));
        buffer.call(AsmValue::Constant(cast_fnptr_usize(inline_tls_pop_disable as usize)));
        buffer.pop(AsmValue::Register(0));
        buffer.popad();
        buffer.stack_add(12 * 4);
        if self.stdcall {
            let stack_arg_count = self.args.iter()
                .filter_map(|x| x.stack_to_opt())
                .count();
            buffer.ret(stack_arg_count * 4);
        } else {
            buffer.ret(0);
        }
    }

    // Returns offset to fix delayed out address
    fn write_out_wrapper(
        &self,
        buffer: &mut AssemblerBuf,
        out_wrapper_pos: AsmFixupPos,
        orig: Option<*const u8>,
    ) -> usize {
        let mut preserved_regs: SmallVec<[u8; 8]> = SmallVec::new();
        buffer.reset_stack_offset();
        buffer.fixup_to_position(out_wrapper_pos);
        for (pos, val) in self.args
                .iter()
                .enumerate()
                .filter_map(|(pos, x)| x.reg_to_opt().map(|x| (pos, x))) {
            if is_preserved_reg(val) {
                buffer.push(AsmValue::Register(val));
                preserved_regs.push(val);
            }
            buffer.mov(AsmValue::Register(val), AsmValue::Stack(pos as i16));
        }
        // Push stack args.
        // Takes possible empty spots into account, so it became kind of complicated.
        let mut stack_args: SmallVec<[_; 8]> = self.args
            .iter()
            .enumerate()
            .filter_map(|(pos, x)| x.stack_to_opt().map(|x| (pos, x)))
            .collect();

        insertion_sort::sort_by_key(&mut stack_args, |&(_, target_pos)| target_pos);
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
            buffer.push(AsmValue::Stack(pos as i16))
        }
        if let Some(s) = stack_args.first() {
            buffer.stack_sub(s.1 as usize * 4);
        }

        let delayed_out = if let Some(orig) = orig {
            // Push return address manually
            unsafe {
                let len = copy_instruction_length(orig, JUMP_INS_LEN);
                let ret_address = buffer.fixup_position();
                buffer.push(AsmValue::Undecided);
                buffer.copy_instructions(orig, len);
                buffer.jump(AsmValue::Constant(orig as u32 + len as u32));
                buffer.fixup_to_position(ret_address);
            }
            !0
        } else {
            buffer.call_const(!0)
        };
        buffer.stack_add(if self.stdcall { 0 } else {
            stack_args.last().map(|x| (x.1 + 1) as usize * 4).unwrap_or(0)
        });
        for &preserved_reg in preserved_regs.iter().rev() {
            buffer.pop(AsmValue::Register(preserved_reg));
        }
        buffer.ret(0);
        delayed_out
    }
}

// Currently really similar impl as in x86_64.rs
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
        self.buf.mov(AsmValue::Register(reg), AsmValue::Stack(i16::from(self.arg_num)));
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
        for (signature_pos, skipped_args) in
            self.current_stack.windows(2).rev()
            .map(|window| (window[0], window[1]))
            // `skipped_args` is the count of unused stack arg positions in between these
            // two which are used.
            .map(|((_, next_pos), (sign_pos, pos))| (sign_pos, pos - next_pos - 1))
            // Special case for the first stack pos.
            .chain(self.current_stack.first().map(|&(sign, actual)| (sign, actual)))
        {
            self.buf.push(AsmValue::Stack(i16::from(signature_pos)));
            self.buf.stack_sub(skipped_args as usize * ptr_size);
        }
        self.buf.call(AsmValue::Constant(addr as u32));
        if !stdcall {
            let stack_size = ptr_size *
                self.current_stack.last().map(|&(_, x)| x as usize + 1).unwrap_or(0);
            self.buf.stack_add(stack_size);
        }
        for reg in self.preserved_regs.iter().rev() {
            self.buf.pop(AsmValue::Register(*reg));
        }
        self.buf.ret(0);
    }

    pub fn write(&mut self, exec_heap: &mut ExecutableHeap) -> *const u8 {
        let data = exec_heap.allocate(self.buf.len());
        self.buf.write(data);
        data
    }

    pub fn next_offset(&mut self) -> usize {
        self.offset_pos += 1;
        self.func_offsets[self.offset_pos - 1]
    }
}

/// Provides a way to reuse the hook wrapper for global module import hooks. Otherwise just
/// a intermediate buffer for the code before it gets placed in exec memory.
pub struct HookWrapCode {
    buf: AssemblerBuf,
    import_fixup_offset: usize,
    // If buf has an exit hook for inlined hooks as well, this is the offset to it.
    exit_wrapper_offset: usize,
    parent_hook_offset: usize,
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
    ///
    /// Also now returns exit hook for inline hooks.
    #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
    pub fn write_wrapper(
        &self,
        entry: Option<*const u8>,
        exit: Option<*const u8>,
        inline_parent_entry: Option<*const u8>,
        heap: &mut ExecutableHeap,
        import_fixup: Option<*const u8>,
    ) -> (GeneratedHook, Option<GeneratedHook>, Option<GeneratedHook>) {
        let ins_len = |x| { unsafe { copy_instruction_length(x, JUMP_INS_LEN) } };

        let entry_orig_ins_len = entry.map(&ins_len).unwrap_or(0);
        let exit_orig_ins_len = exit.map(&ins_len).unwrap_or(0);
        let parent_orig_ins_len = inline_parent_entry.map(&ins_len).unwrap_or(0);

        let wrapper_len =
            align(self.buf.len(), 4) +
            align(entry_orig_ins_len, 4) +
            align(exit_orig_ins_len, 4) +
            align(parent_orig_ins_len + 0xc, 4);
        let data = heap.allocate(wrapper_len);
        let entry_orig_ins_ptr = data;
        let exit_orig_ins_ptr = unsafe {
            entry_orig_ins_ptr.offset(align(entry_orig_ins_len, 4) as isize)
        };
        let parent_orig_ins_ptr = unsafe {
            exit_orig_ins_ptr.offset(align(exit_orig_ins_len, 4) as isize)
        };
        let wrapper = unsafe {
            parent_orig_ins_ptr.offset(align(parent_orig_ins_len, 4) as isize)
        };
        let wrapper_end = unsafe {
            wrapper.offset(align(self.buf.len(), 4) as isize)
        };
        if let Some(entry) = entry {
            unsafe { ptr::copy_nonoverlapping(entry, entry_orig_ins_ptr, entry_orig_ins_len) };
        }
        if let Some(exit) = exit {
            unsafe { ptr::copy_nonoverlapping(exit, exit_orig_ins_ptr, exit_orig_ins_len) };
        }
        if let Some(parent) = inline_parent_entry {
            unsafe { ptr::copy_nonoverlapping(parent, parent_orig_ins_ptr, parent_orig_ins_len) };
        }
        let exit_wrapper = unsafe { wrapper.offset(self.exit_wrapper_offset as isize) };
        let parent_hook = unsafe { wrapper.offset(self.parent_hook_offset as isize) };
        self.buf.write(wrapper);
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
            let ptr = wrapper_end.offset(4) as *mut *const u8;
            *ptr = exit_wrapper;
            ptr
        };
        let parent_pointer_to_wrapper = unsafe {
            let ptr = wrapper_end.offset(8) as *mut *const u8;
            *ptr = parent_hook;
            ptr
        };
        assert_eq!(parent_pointer_to_wrapper as usize + 4, data as usize + wrapper_len);
        let entry = GeneratedHook {
            wrapper,
            orig_ins_len: entry_orig_ins_len,
            orig_ins: entry_orig_ins_ptr,
            pointer_to_wrapper: entry_pointer_to_wrapper,
        };
        let exit = exit.map(|_| GeneratedHook {
            wrapper: exit_wrapper,
            orig_ins_len: exit_orig_ins_len,
            orig_ins: exit_orig_ins_ptr,
            pointer_to_wrapper: exit_pointer_to_wrapper,
        });
        let parent = inline_parent_entry.map(|_| GeneratedHook {
            wrapper: parent_hook,
            orig_ins_len: parent_orig_ins_len,
            orig_ins: parent_orig_ins_ptr,
            pointer_to_wrapper: parent_pointer_to_wrapper,
        });
        (entry, exit, parent)
    }
}

struct AssemblerBuf {
    buf: Vec<u8>,
    fixups: SmallVec<[usize; 8]>,
    // Import hooks
    stack_offset: i32,
}

#[derive(Copy, Clone)]
pub struct AsmFixupPos(usize);

impl AssemblerBuf {
    pub fn new() -> AssemblerBuf {
        AssemblerBuf {
            // TODO INSTRUCTION COPYING BREAKS IF THE VECTOR IS REALLOCATED
            buf: Vec::with_capacity(512),
            fixups: SmallVec::new(),
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
        let off = self.fixups[fixup_pos.0];
        let val = self.buf.len() as u32;
        LE::write_u32(&mut self.buf[off..(off + 4)], val);
    }

    pub unsafe fn copy_instructions(&mut self, source: *const u8, amt: usize) {
        // TODO HAVE IMAGINED BASE BE IN SELF
        let ptr = self.buf.as_ptr();
        copy_instructions(source, &mut self.buf, ptr, amt);
    }

    fn write(&self, out: *mut u8) {
        let diff = out as usize;
        unsafe {
            // TODO USE IMAGINED BASE
            copy_instructions_ignore_shortjmp(&self.buf, out);
            for &fixup in self.fixups.iter() {
                let prev = LE::read_u32(&self.buf[fixup..(fixup + 4)]);
                write_unaligned(out.offset(fixup as isize), prev.wrapping_add(diff as u32));
            }
        }
    }

    pub fn pushfd(&mut self) {
        self.buf.push(0x9c);
    }

    pub fn push(&mut self, val: AsmValue) {
        match val {
            AsmValue::Undecided => {
                self.buf.push(0x68);
                self.fixups.push(self.buf.len());
                self.buf.extend_from_slice(&0u32.to_le_bytes());
            }
            AsmValue::Constant(val) => {
                self.buf.push(0x68);
                self.buf.extend_from_slice(&(val as u32).to_le_bytes());
            }
            AsmValue::Register(reg) => {
                self.buf.push(0x50 + reg);
            }
            AsmValue::Stack(pos) => {
                let offset = i32::from(pos * 4) + self.stack_offset + 4;
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
            AsmValue::EaxPtr(_) => unimplemented!(),
        }
        self.stack_offset += 4;
    }

    pub fn pop(&mut self, val: AsmValue) {
        match val {
            AsmValue::Register(reg) => {
                self.buf.push(0x58 + reg);
            }
            _ => unimplemented!(),
        }
        self.stack_offset -= 4;
    }

    pub fn pushad(&mut self) {
        self.buf.push(0x60);
        self.stack_offset += 8 * 4;
    }

    pub fn popad(&mut self) {
        self.buf.push(0x61);
        self.stack_offset -= 8 * 4;
    }

    pub fn mov(&mut self, to: AsmValue, from: AsmValue) {
        match (to, from) {
            (AsmValue::Register(to), AsmValue::Register(from)) => {
                if to != from {
                    self.buf.extend_from_slice(&[0x89, 0xc0 + from * 8 + to]);
                }
            }
            (AsmValue::Register(to), AsmValue::Stack(from)) => {
                let offset = (i32::from(from) * 4) + 4 + self.stack_offset;
                match offset {
                    0 => {
                        self.buf.extend_from_slice(&[0x8b, 0x4 + to * 8, 0xe4]);
                    }
                    x if x < 0x80 => {
                        self.buf.extend_from_slice(&[0x8b, 0x44 + to * 8, 0xe4, x as u8]);
                    }
                    x => {
                        self.buf.extend_from_slice(&[0x8b, 0x84 + to * 8, 0xe4]);
                        self.buf.extend_from_slice(&(x as u32).to_le_bytes());
                    }
                }
            }
            (AsmValue::Register(to), AsmValue::EaxPtr(offset)) => {
                self.buf.extend_from_slice(&[0x8b, 0x40 + to * 8, offset as u8]);
            }
            (_, _) => unimplemented!(),
        }
    }

    pub fn mov_reg_offset(&mut self, to: AsmValue, from: AsmValue, reg: u8) {
        match (to, from) {
            (AsmValue::Register(to), AsmValue::Stack(from)) => {
                let offset = (i32::from(from) * 4) + 4 + self.stack_offset;
                match offset {
                    0 => {
                        self.buf.extend_from_slice(&[0x8b, 0x4 + to * 8, 0x04 + reg * 8]);
                    }
                    x if x < 0x80 => {
                        self.buf.extend_from_slice(
                            &[0x8b, 0x44 + to * 8, 0x04 + reg * 8, x as u8],
                        );
                    }
                    x => {
                        self.buf.extend_from_slice(&[0x8b, 0x84 + to * 8, 0x04 + reg * 8]);
                        self.buf.extend_from_slice(&(x as u32).to_le_bytes());
                    }
                }
            }
            (_, _) => unimplemented!(),
        }
    }

    fn stack_add_sub(&mut self, value: usize, add: bool) {
        let byte2;
        if add {
            self.stack_offset -= value as i32;
            byte2 = 0xc4;
        } else {
            self.stack_offset += value as i32;
            byte2 = 0xec;
        }
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.extend_from_slice(&[0x83, byte2, x as u8]);
            }
            x => {
                self.buf.extend_from_slice(&[0x81, byte2]);
                self.buf.extend_from_slice(&(x as u32).to_le_bytes());
            }
        }
    }

    pub fn stack_add(&mut self, value: usize) {
        self.stack_add_sub(value, true)
    }

    pub fn stack_sub(&mut self, value: usize) {
        self.stack_add_sub(value, false)
    }

    // NOTE: WONT UPDATE STACK OFFSET BECAUSE IT CANT
    pub fn stack_sub_reg(&mut self, register: u8) {
        self.buf.extend_from_slice(&[0x29, 0xc4 + register * 8]);
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
                self.jump_call_const(dest, true);
            }
            AsmValue::Register(dest) => {
                self.buf.extend_from_slice(&[0xff, 0xe0 + dest]);
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
                self.buf.extend_from_slice(&[0xff, 0xd0 + dest]);
            }
            _ => unimplemented!(),
        }
    }

    // Returns position of dest so it can be overwritten later
    pub fn call_const(&mut self, target: u32) -> usize {
        self.jump_call_const(target, false)
    }

    fn jump_call_const(&mut self, target: u32, is_jump: bool) -> usize {
        let ret = self.buf.len() + 4;
        let jump_or_call = if is_jump { 0x64 } else { 0x54 };
        // Mov [esp-4], addr; call/jump [esp - 4]
        // TODO It's actually pretty bad to assume that values even one word
        // above esp can be relied on. Should do something else.
        let mut slice = [
            0xc7, 0x44, 0xe4, 0xfc, 0x00, 0x00, 0x00, 0x00,
            0xff, jump_or_call, 0xe4, 0xfc,
        ];
        LE::write_u32(&mut slice[4..8], target);
        self.buf.extend_from_slice(&slice);
        ret
    }
}

pub unsafe fn copy_instruction_length(ins: *const u8, min_length: usize) -> usize {
    let mut sum = 0;
    for (opcode, _) in lde::X86.iter(slice::from_raw_parts(ins, min_length + 32), 0) {
        if sum >= min_length {
            break;
        }
        sum += opcode.len();
    }
    sum
}

// Assumes that short jumps won't need to be changed
unsafe fn copy_instructions_ignore_shortjmp(
    src: &[u8],
    mut dst: *mut u8,
) {
    let mut len = src.len() as isize;
    for (opcode, _) in lde::X86.iter(src, 0) {
        if len <= 0 {
            return;
        }
        let ins_len = opcode.len() as isize;
        // Relative jumps need to be handled differently
        match opcode[0] {
            0xf => match opcode[1] {
                0x80 ..= 0x8f => {
                    ptr::copy_nonoverlapping(opcode.as_ptr(), dst, 6);
                    let diff = (dst as usize).wrapping_sub(opcode.as_ptr() as usize);
                    let value = read_unaligned::<usize>(dst.offset(2));
                    write_unaligned(dst.offset(2), value.wrapping_sub(diff));
                }
                _ => ptr::copy_nonoverlapping(opcode.as_ptr(), dst, ins_len as usize),
            },
            0xe8 | 0xe9 => {
                assert!(ins_len == 5);
                ptr::copy_nonoverlapping(opcode.as_ptr(), dst, 5);
                let diff = (dst as usize).wrapping_sub(opcode.as_ptr() as usize);
                let value = read_unaligned::<usize>(dst.offset(1));
                write_unaligned(dst.offset(1), value.wrapping_sub(diff));
            }
            _ => ptr::copy_nonoverlapping(opcode.as_ptr(), dst, ins_len as usize),
        }
        dst = dst.offset(ins_len);
        len -= ins_len;
    }
    if len != 0 {
        panic!("Could not disassemble {:02x?}", src);
    }
}

// Dst_base is the address at which the code is *imagined* to be at, so it won't matter if
// the vector is reallocated.
//
// (The rest of the code doesn't actually work with that yet though)
unsafe fn copy_instructions(
    src: *const u8,
    dst: &mut Vec<u8>,
    dst_base: *const u8,
    min_length: usize,
) {
    let mut len = min_length as isize;
    for (opcode, _) in lde::X86.iter(slice::from_raw_parts(src, min_length + 32), 0) {
        if len <= 0 {
            return;
        }
        let ins_len = opcode.len() as isize;
        match opcode[0] {
            0x0f => match opcode[1] {
                // Long cond jump
                0x80 ..= 0x8f => {
                    let diff = (dst_base as usize + dst.len())
                        .wrapping_sub(opcode.as_ptr() as usize);
                    dst.push(0xf);
                    dst.push(opcode[1]);
                    let offset = LE::read_u32(&opcode[2..6]);
                    dst.extend_from_slice(&offset.wrapping_sub(diff as u32).to_le_bytes());
                }
                _ => {
                    let slice = slice::from_raw_parts(opcode.as_ptr(), ins_len as usize);
                    dst.extend_from_slice(slice);
                }
            },
            // Short cond jump
            0x70 ..= 0x7f => {
                let diff = (dst_base as usize + dst.len() + 6)
                    .wrapping_sub(opcode.as_ptr() as usize + 2);
                let offset = opcode[1] as i8 as u32;
                dst.push(0xf);
                dst.push(opcode[0] + 0x10);
                dst.extend_from_slice(&offset.wrapping_sub(diff as u32).to_le_bytes());
            }
            0xe8 | 0xe9 => {
                assert!(ins_len == 5);
                let diff = (dst_base as usize + dst.len()).wrapping_sub(opcode.as_ptr() as usize);
                dst.push(opcode[0]);
                let offset = LE::read_u32(&opcode[1..5]);
                dst.extend_from_slice(&offset.wrapping_sub(diff as u32).to_le_bytes());
            }
            // Short jump
            0xeb => {
                let diff = (dst_base as usize + dst.len() + 5)
                    .wrapping_sub(opcode.as_ptr() as usize + 2);
                let offset = opcode[1] as i8 as u32;
                dst.push(0xe9);
                dst.extend_from_slice(&offset.wrapping_sub(diff as u32).to_le_bytes());
            }
            _ => {
                let slice = slice::from_raw_parts(opcode.as_ptr(), ins_len as usize);
                dst.extend_from_slice(slice);
            }
        }
        len -= ins_len;
    }
    if len != 0 {
        panic!("Could not disassemble {:x}", src as usize);
    }
}
