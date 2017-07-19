use std::mem;
use std::ptr;
use std::slice;
use std::io::Write;

use lde::{self, InsnSet};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use smallvec::SmallVec;

use OrigFuncCallback;
pub use win_common::*;

#[inline]
pub unsafe fn write_jump(from: *mut u8, to: *const u8) {
    *from = 0xe9;
    *(from.offset(1) as *mut usize) = (to as usize).wrapping_sub(from as usize).wrapping_sub(5);
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
    preserved_regs: SmallVec<[(u8); 8]>,
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
    Constant(u32),
}

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
}

impl HookWrapAssembler {
    pub fn new(rust_in_wrapper: *const u8, target: *const u8, stdcall: bool) -> HookWrapAssembler
    {
        HookWrapAssembler {
            rust_in_wrapper: rust_in_wrapper,
            stdcall: stdcall,
            target: target,
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
        let out_wrapper_pos = self.write_in_wrapper(&mut buffer, orig);
        // Only write out wrappers when needed
        let delayed_out = match orig {
            OrigFuncCallback::Overwritten(orig) => {
                self.write_out_wrapper(&mut buffer, out_wrapper_pos, Some(orig))
            }
            OrigFuncCallback::ImportHook => {
                self.write_out_wrapper(&mut buffer, out_wrapper_pos, None)
            }
            OrigFuncCallback::None | OrigFuncCallback::Hook(_) => !0,
        };
        HookWrapCode {
            buf: buffer,
            import_fixup_offset: delayed_out,
        }
    }

    // Returns fixup pos for out_wrapper's address
    fn write_in_wrapper(&self, buffer: &mut AssemblerBuf, orig: OrigFuncCallback) -> AsmFixupPos {
        if let OrigFuncCallback::Hook(_) = orig {
            buffer.pushad();
        }
        buffer.push(AsmValue::Constant(self.target as u32));
        let out_wrapper_pos = buffer.fixup_position();
        buffer.push(AsmValue::Undecided);
        for val in self.args.iter().rev() {
            buffer.push(AsmValue::from_loc(val));
        }
        buffer.call(AsmValue::Constant(self.rust_in_wrapper as u32));
        buffer.stack_add((self.args.len() + 2) * 4);
        if let OrigFuncCallback::Hook(orig) = orig {
            buffer.popad();
            unsafe {
                let len = copy_instruction_length(orig, 5);
                buffer.copy_instructions(orig, len);
                buffer.jump(AsmValue::Constant(orig as u32 + len as u32));
            }
        } else {
            if self.stdcall {
                let stack_arg_count = self.args.iter().filter_map(|x| x.stack_to_opt()).count();
                buffer.ret(stack_arg_count * 4);
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

        stack_args.sort_by_key(|&(_, target_pos)| target_pos);
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
                let len = copy_instruction_length(orig, 5);
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
    pub fn stack(&mut self, pos: i32) {
        self.current_stack.push((self.arg_num, pos as u8));
        self.arg_num += 1;
    }

    pub fn register(&mut self, reg: u8) {
        if is_preserved_reg(reg) {
            self.buf.push(AsmValue::Register(reg));
            self.preserved_regs.push(reg);
        }
        self.buf.mov(AsmValue::Register(reg), AsmValue::Stack(self.arg_num as i16));
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
        self.current_stack.sort_by_key(|&(_, x)| x);
        for (signature_pos, skipped_args) in
            self.current_stack.windows(2).rev()
            .map(|window| (window[0], window[1]))
            // `skipped_args` is the count of unused stack arg positions in between these
            // two which are used.
            .map(|((_, next_pos), (sign_pos, pos))| (sign_pos, pos - next_pos - 1))
            // Special case for the first stack pos.
            .chain(self.current_stack.first().map(|&(sign, actual)| (sign, actual)))
        {
            self.buf.push(AsmValue::Stack(signature_pos as i16));
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
}

impl HookWrapCode {
    /// Allocates a chunk of executable memory and writes all parts of function entry wrapper
    /// there. (Original code, in wrapper, out wrapper, rust objects), in that order.
    ///
    /// Returns pointer to the wrapper and original instruction length.
    /// The original instructions will be copied to memory right before the wrapper,
    /// to be used when patch is disabled.
    pub fn write_wrapper(&self,
                         orig: Option<*const u8>,
                         heap: &mut ExecutableHeap,
                         import_fixup: Option<*const u8>,
                        ) -> (*const u8, usize)
    {
        let orig_ins_len = match orig {
            Some(orig) => { unsafe { copy_instruction_length(orig, 5) } },
            None => 0,
        };
        let wrapper_len = self.buf.len() + orig_ins_len;
        let data = heap.allocate(wrapper_len);
        if let Some(orig) = orig {
            unsafe { ptr::copy_nonoverlapping(orig, data, orig_ins_len) };
        }
        let wrapper = unsafe { data.offset(orig_ins_len as isize) };
        self.buf.write(wrapper);
        if let Some(fixup) = import_fixup {
            unsafe {
                let offset = self.import_fixup_offset as isize;
                *(wrapper.offset(offset) as *mut usize) = fixup as usize;
            }
        }
        (wrapper, orig_ins_len)
    }
}

struct AssemblerBuf {
    buf: Vec<u8>,
    fixups: SmallVec<[usize; 8]>,
    // Import hooks
    stack_offset: i32,
}

pub struct AsmFixupPos(usize);

impl AssemblerBuf {
    pub fn new() -> AssemblerBuf {
        AssemblerBuf {
            buf: Vec::with_capacity(128),
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
        (&mut self.buf[off .. off + 4]).write_u32::<LittleEndian>(val).unwrap();
    }

    pub unsafe fn copy_instructions(&mut self, source: *const u8, amt: usize) {
        self.buf.reserve(amt);
        copy_instructions(source, self.buf.as_mut_ptr().offset(self.buf.len() as isize), amt);
        let new_len = self.buf.len() + amt;
        self.buf.set_len(new_len);
    }

    fn write(&self, out: *mut u8) {
        let diff = out as usize;
        unsafe {
            copy_instructions(self.buf.as_ptr(), out, self.buf.len());
            for &fixup in self.fixups.iter() {
                let prev = (&self.buf[fixup .. fixup + 4]).read_u32::<LittleEndian>().unwrap();
                *(out.offset(fixup as isize) as *mut u32) = prev.wrapping_add(diff as u32);
            }
        }
    }

    pub fn push(&mut self, val: AsmValue) {
        match val {
            AsmValue::Undecided => {
                self.buf.write_u8(0x68).unwrap();
                self.fixups.push(self.buf.len());
                self.buf.write_u32::<LittleEndian>(0).unwrap();
            }
            AsmValue::Constant(val) => {
                self.buf.write_u8(0x68).unwrap();
                self.buf.write_u32::<LittleEndian>(val).unwrap();
            }
            AsmValue::Register(reg) => {
                self.buf.write_u8(0x50 + reg).unwrap();
            }
            AsmValue::Stack(pos) => {
                let offset = (pos * 4) as i32 + self.stack_offset + 4;
                match offset {
                    0 => {
                        self.buf.write(&[0xff, 0x34, 0xe4]).unwrap();
                    }
                    x if x < 0x80 => {
                        self.buf.write(&[0xff, 0x74, 0xe4, x as u8]).unwrap();
                    }
                    x => {
                        self.buf.write(&[0xff, 0xb4, 0xe4]).unwrap();
                        self.buf.write_u32::<LittleEndian>(x as u32).unwrap();
                    }
                }
            }
        }
        self.stack_offset += 4;
    }

    pub fn pop(&mut self, val: AsmValue) {
        match val {
            AsmValue::Register(reg) => {
                self.buf.write_u8(0x58 + reg).unwrap();
            }
            _ => unimplemented!(),
        }
        self.stack_offset += 4;
    }

    pub fn pushad(&mut self) {
        self.buf.write_u8(0x60).unwrap();
        self.stack_offset += 8 * 4;
    }

    pub fn popad(&mut self) {
        self.buf.write_u8(0x61).unwrap();
        self.stack_offset -= 8 * 4;
    }

    pub fn mov(&mut self, to: AsmValue, from: AsmValue) {
        match (to, from) {
            (AsmValue::Register(to), AsmValue::Register(from)) => {
                if to != from {
                    self.buf.write_u8(0x89).unwrap();
                    self.buf.write_u8(0xc0 + from * 8 + to).unwrap();
                }
            }
            (AsmValue::Register(to), AsmValue::Stack(from)) => {
                let offset = (from * 4) as i32 + self.stack_offset + 4;
                match offset {
                    0 => {
                        self.buf.write(&[0x8b, 0x4 + to * 8, 0xe4]).unwrap();
                    }
                    x if x < 0x80 => {
                        self.buf.write(&[0x8b, 0x44 + to * 8, 0xe4, x as u8]).unwrap();
                    }
                    x => {
                        self.buf.write(&[0x8b, 0x84 + to * 8, 0xe4]).unwrap();
                        self.buf.write_u32::<LittleEndian>(x as u32).unwrap();
                    }
                }
            }
            (_, _) => unimplemented!(),
        }
    }

    pub fn stack_add(&mut self, value: usize) {
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.write(&[0x83, 0xc4, x as u8]).unwrap();
            }
            x => {
                self.buf.write(&[0x81, 0xc4]).unwrap();
                self.buf.write_u32::<LittleEndian>(x as u32).unwrap();
            }
        }
        self.stack_offset -= value as i32;
    }

    pub fn stack_sub(&mut self, value: usize) {
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.write(&[0x83, 0xec, x as u8]).unwrap();
            }
            x => {
                self.buf.write(&[0x81, 0xec]).unwrap();
                self.buf.write_u32::<LittleEndian>(x as u32).unwrap();
            }
        }
        self.stack_offset += value as i32;
    }

    pub fn ret(&mut self, stack_pop: usize) {
        if stack_pop == 0 {
            self.buf.write_u8(0xc3).unwrap();
        } else {
            self.buf.write_u8(0xc2).unwrap();
            self.buf.write_u16::<LittleEndian>(stack_pop as u16).unwrap();
        }
    }

    pub fn jump(&mut self, target: AsmValue) {
        match target {
            AsmValue::Constant(dest) => {
                self.buf.write(&[0xc7, 0x44, 0xe4, 0xfc]).unwrap();
                self.buf.write_u32::<LittleEndian>(dest).unwrap();
                self.buf.write(&[0xff, 0x64, 0xe4, 0xfc]).unwrap();
            }
            AsmValue::Register(dest) => {
                self.buf.write(&[0xff, 0xe0 + dest]).unwrap();
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
                self.buf.write(&[0xff, 0xd0 + dest]).unwrap();
            }
            _ => unimplemented!(),
        }
    }

    // Returns position of dest so it can be overwritten later
    pub fn call_const(&mut self, target: u32) -> usize {
        // Mov [esp-4], addr; call [esp - 4]
        self.buf.write(&[0xc7, 0x44, 0xe4, 0xfc]).unwrap();
        let ret = self.buf.len();
        self.buf.write_u32::<LittleEndian>(target).unwrap();
        self.buf.write(&[0xff, 0x54, 0xe4, 0xfc]).unwrap();
        ret
    }
}

pub unsafe fn copy_instruction_length(ins: *const u8, min_length: usize) -> usize {
    let mut sum = 0;
    for (opcode, _) in lde::x86::lde(slice::from_raw_parts(ins, min_length + 32), 0) {
        if sum >= min_length {
            break;
        }
        sum += opcode.len();
    }
    sum
}

unsafe fn copy_instructions(src: *const u8, mut dst: *mut u8, min_length: usize) {
    let mut len = min_length as isize;
    for (opcode, _) in lde::x86::lde(slice::from_raw_parts(src, min_length + 32), 0) {
        if len <= 0 {
            return;
        }
        let ins_len = opcode.len() as isize;
        // Relative jumps need to be handled differently
        match opcode[0] {
            0xe8 | 0xe9 => {
                assert!(ins_len == 5);
                ptr::copy_nonoverlapping(opcode.as_ptr(), dst, 5);
                let diff = (dst as usize).wrapping_sub(opcode.as_ptr() as usize);
                let value = *(dst.offset(1) as *mut usize);
                *(dst.offset(1) as *mut usize) = value.wrapping_sub(diff);

            }
            _ => ptr::copy_nonoverlapping(opcode.as_ptr(), dst, ins_len as usize),
        }
        dst = dst.offset(ins_len);
        len -= ins_len;
    }
    panic!("Could not disassemble {:x}", src as usize);
}
