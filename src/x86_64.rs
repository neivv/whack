use std::mem;
use std::ptr;
use std::slice;
use std::io::Write;

use lde::{self, InsnSet};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use smallvec::SmallVec;

use insertion_sort;
use OrigFuncCallback;
pub use win_common::*;

#[inline]
pub unsafe fn write_jump(from: *mut u8, to: *const u8) {
    *from = 0xff;
    *from.offset(1) = 0x25;
    *(from.offset(2) as *mut u32) = 0;
    *(from.offset(6) as *mut usize) = to as usize;
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
            n => AsmValue::Stack(n as i16),
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
            OrigFuncCallback::None | OrigFuncCallback::Hook(_) => None,
        };
        buffer.align(16);
        let const_offsets = buffer.write_fixups();

        HookWrapCode {
            buf: buffer,
            import_fixup_offset: import_fixup_offset.map(|x| const_offsets.to_offset(x))
                .unwrap_or(0),
        }
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
                let len = ins_len(orig, 6 + 8);
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
    pub fn stack(&mut self, pos: i32) {
        self.current_stack.push((self.arg_num, pos as u8));
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
        self.buf.write(data);
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
            Some(orig) => { unsafe { ins_len(orig, 14) } },
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
        self.buf.reserve(amt);
        copy_instructions(self.buf.as_mut_ptr().offset(self.buf.len() as isize), source, amt);
        let new_len = self.buf.len() + amt;
        self.buf.set_len(new_len);
    }

    fn write_fixups(&mut self) -> ConstOffsets {
        let const_offset_begin = self.buf.len() + self.fixups.len() * 8;
        for &(fixup, value) in self.fixups.iter().chain(self.constants.iter()) {
            let offset = self.buf.len() - fixup - 4;
            self.buf.write_u64::<LittleEndian>(value).unwrap();
            (&mut self.buf[fixup .. fixup + 4]).write_u32::<LittleEndian>(offset as u32).unwrap();
        }
        self.align(16);
        ConstOffsets(const_offset_begin)
    }

    pub fn write(&self, out: *mut u8) {
        let diff = out as usize;
        unsafe {
            ptr::copy_nonoverlapping(self.buf.as_ptr(), out, self.buf.len());
            for &(fixup, value) in self.fixups.iter() {
                let value_pos = fixup + 4 +
                    (&self.buf[fixup .. fixup + 4]).read_u32::<LittleEndian>().unwrap() as usize;
                *(out.offset(value_pos as isize) as *mut u64) = value.wrapping_add(diff as u64);
            }
        }
    }

    pub fn push(&mut self, val: AsmValue) {
        match val {
            AsmValue::Undecided => {
                self.buf.write(&[0xff, 0x35]).unwrap();
                self.fixups.push((self.buf.len(), 0));
                self.buf.write_u32::<LittleEndian>(0).unwrap();
            }
            AsmValue::Constant(val) => {
                self.buf.write(&[0xff, 0x35]).unwrap();
                self.constants.push((self.buf.len(), val));
                self.buf.write_u32::<LittleEndian>(0).unwrap();
            }
            AsmValue::Register(reg) => {
                if reg >= 8 {
                    self.buf.write_u8(0x41).unwrap();
                }
                self.buf.write_u8(0x50 + (reg & 7)).unwrap();
            }
            AsmValue::Stack(pos) => {
                let offset = (pos * 8) as i32 + self.stack_offset + 8;
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
        self.stack_offset += 8;
    }

    pub fn pop(&mut self, val: AsmValue) {
        match val {
            AsmValue::Register(reg) => {
                if reg >= 8 {
                    self.buf.write_u8(0x41).unwrap();
                }
                self.buf.write_u8(0x58 + (reg & 7)).unwrap();
            }
            _ => unimplemented!(),
        }
        self.stack_offset -= 8;
    }

    pub fn pushad(&mut self) {
        for x in 0x50..0x55 {
            self.buf.write_u8(x).unwrap();
        }
        // Skip rsp
        for x in 0x56..0x58 {
            self.buf.write_u8(x).unwrap();
        }
        for x in 0x50..0x58 {
            self.buf.write(&[0x41, x]).unwrap();
        }
        self.stack_offset += 15 * 8;
    }

    pub fn popad(&mut self) {
        for x in (0x58..0x60).rev() {
            self.buf.write(&[0x41, x]).unwrap();
        }
        for x in (0x5e..0x60).rev() {
            self.buf.write_u8(x).unwrap();
        }
        // Skip rsp
        for x in (0x58..0x5d).rev() {
            self.buf.write_u8(x).unwrap();
        }
        self.stack_offset -= 15 * 8;
    }

    pub fn mov(&mut self, to: AsmValue, from: AsmValue) {
        match (to, from) {
            (AsmValue::Register(to), AsmValue::Register(from)) => {
                if to != from {
                    let reg_spec_byte = 0x48 + if to >= 8 { 1 } else { 0 } +
                        if from >= 8 { 4 } else { 0 };
                    self.buf.write_u8(reg_spec_byte).unwrap();
                    self.buf.write_u8(0x89).unwrap();
                    self.buf.write_u8(0xc0 + (from & 7) * 8 + (to & 7)).unwrap();
                }
            }
            (AsmValue::Register(to), AsmValue::Stack(from)) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.write_u8(reg_spec_byte).unwrap();
                let offset = (from as i32 * 8) + 8 + self.stack_offset;
                match offset {
                    0 => {
                        self.buf.write(&[0x8b, 0x4 + (to & 7) * 8, 0xe4]).unwrap();
                    }
                    x if x < 0x80 => {
                        self.buf.write(&[0x8b, 0x44 + (to & 7) * 8, 0xe4, x as u8]).unwrap();
                    }
                    x => {
                        self.buf.write(&[0x8b, 0x84 + (to & 7) * 8, 0xe4]).unwrap();
                        self.buf.write_u32::<LittleEndian>(x as u32).unwrap();
                    }
                }
            }
            (AsmValue::Register(to), AsmValue::Undecided) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.write_u8(reg_spec_byte).unwrap();
                self.buf.write_u8(0x8b).unwrap();
                self.buf.write_u8(0x5 + (to & 7) * 8).unwrap();
                self.fixups.push((self.buf.len(), 0));
                self.buf.write_u32::<LittleEndian>(0).unwrap();
            }
            (AsmValue::Register(to), AsmValue::Constant(val)) => {
                let reg_spec_byte = 0x48 + if to >= 8 { 4 } else { 0 };
                self.buf.write(&[reg_spec_byte, 0x8b, (to & 7) * 8 + 0x5]).unwrap();
                self.constants.push((self.buf.len(), val));
                self.buf.write_u32::<LittleEndian>(0).unwrap();
            }
            (_, _) => unimplemented!(),
        }
    }

    pub fn stack_add(&mut self, value: usize) {
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.write(&[0x48, 0x83, 0xc4, x as u8]).unwrap();
            }
            x => {
                self.buf.write(&[0x48, 0x81, 0xc4]).unwrap();
                self.buf.write_u32::<LittleEndian>(x as u32).unwrap();
            }
        }
        self.stack_offset -= value as i32;
    }

    pub fn stack_sub(&mut self, value: usize) {
        match value {
            0 => (),
            x if x < 0x80 => {
                self.buf.write(&[0x48, 0x83, 0xec, x as u8]).unwrap();
            }
            x => {
                self.buf.write(&[0x48, 0x81, 0xec]).unwrap();
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
                self.buf.write(&[0xff, 0x25]).unwrap();
                self.constants.push((self.buf.len(), dest));
                self.buf.write_u32::<LittleEndian>(0).unwrap();
            }
            AsmValue::Register(dest) => {
                if dest >= 8 {
                    self.buf.write_u8(0x41).unwrap();
                }
                self.buf.write(&[0xff, 0xe0 + (dest & 7)]).unwrap();
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
                    self.buf.write_u8(0x41).unwrap();
                }
                self.buf.write(&[0xff, 0xd0 + (dest & 7)]).unwrap();
            }
            _ => unimplemented!(),
        }
    }

    fn call_const(&mut self, val: u64) -> ConstOffset{
        self.buf.write(&[0xff, 0x15]).unwrap();
        self.constants.push((self.buf.len(), val));
        self.buf.write_u32::<LittleEndian>(0).unwrap();
        ConstOffset(self.constants.len() - 1)
    }
}

unsafe fn copy_instructions(to: *mut u8, from: *const u8, min_len: usize) -> usize {
    let len = ins_len(from, min_len);
    ::std::ptr::copy_nonoverlapping(from, to, len);
    len
}

pub unsafe fn ins_len(ins: *const u8, min_length: usize) -> usize {
    let mut sum = 0;
    for (opcode, _) in lde::x64::lde(slice::from_raw_parts(ins, min_length + 32), 0) {
        if sum >= min_length {
            break;
        }
        sum += opcode.len();
    }
    sum
}
