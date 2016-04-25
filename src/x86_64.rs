use std::io::Write;
use std::ptr;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use smallvec::SmallVec;

pub use win_common::*;

#[inline]
pub unsafe fn write_jump(from: *mut u8, to: *const u8) {
    *from = 0xff;
    *from.offset(1) = 0x25;
    *(from.offset(2) as *mut usize) = 0;
    *(from.offset(6) as *mut usize) = to as usize;
}

pub struct WrapAssembler {
    orig: *mut u8,
    fnptr_hook: bool,
    stdcall: bool,
    args: SmallVec<[Location; 8]>,
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

impl WrapAssembler {
    pub fn new(orig_addr: *mut u8, fnptr_hook: bool, stdcall: bool) -> WrapAssembler {
        WrapAssembler {
            orig: orig_addr,
            fnptr_hook: fnptr_hook,
            stdcall: stdcall,
            args: SmallVec::new(),
        }
    }

    pub fn add_arg(&mut self, arg: Location) {
        assert!(self.args.iter().find(|&&a| a == arg).is_none());
        self.args.push(arg);
    }

    fn write_common(self, rust_in_wrapper: *const u8) -> AssemblerBuf {
        let mut stack_args: SmallVec<[_; 8]> = self.args
            .iter()
            .enumerate()
            .filter_map(|(pos, x)| x.stack_to_opt().map(|x| (pos, x)))
            .collect();

        let mut buffer = AssemblerBuf::new();
        let target_addr_pos = buffer.fixup_position();
        match self.args.len() {
            0 => buffer.mov(AsmValue::Register(2), AsmValue::Undecided),
            1 => buffer.mov(AsmValue::Register(8), AsmValue::Undecided),
            2 => buffer.mov(AsmValue::Register(9), AsmValue::Undecided),
            _ => buffer.push(AsmValue::Undecided),
        }
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
        buffer.call(AsmValue::Constant(rust_in_wrapper as u64));
        buffer.stack_add(::std::cmp::max((self.args.len() + 2) * 8, 0x20));
        buffer.ret(if self.stdcall { stack_args.len() * 8 } else { 0 });

        buffer.reset_stack_offset();
        buffer.fixup_to_position(out_wrapper_pos);
        // Push stack args.
        // Takes possible empty spots into account, so it became kind of complicated.
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
        if !self.fnptr_hook {
            // Push return address manually
            unsafe {
                let len = ins_len(self.orig, 6 + 8);
                let ret_address = buffer.fixup_position();
                buffer.push(AsmValue::Undecided);
                buffer.copy_instructions(self.orig, len);
                buffer.jump(AsmValue::Constant(self.orig as u64 + len as u64));
                buffer.fixup_to_position(ret_address);
            }
        } else {
            buffer.call(AsmValue::Constant(self.orig as u64));
        };
        buffer.stack_add(if self.stdcall { 0 } else {
            stack_args.last().map(|x| (x.1 + 1) as usize * 8).unwrap_or(0x20)
        });
        buffer.ret(0);
        buffer.align(16);
        buffer.write_fixups();
        buffer.fixup_to_position(target_addr_pos);
        buffer
    }

    pub fn write<Cb>(self,
                     heap: &mut ExecutableHeap,
                     rust_in_wrapper: *const u8,
                     target_len: usize,
                     write_callback: Cb,
                    ) -> *const u8
    where Cb: FnOnce(*mut u8),
    {
        let mut buffer = self.write_common(rust_in_wrapper);
        buffer.write(heap, target_len, write_callback)
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

    pub fn reset_stack_offset(&mut self) {
        self.stack_offset = 0;
    }

    pub fn fixup_position(&mut self) -> AsmFixupPos {
        AsmFixupPos(self.fixups.len())
    }

    pub fn fixup_to_position(&mut self, fixup_pos: AsmFixupPos) {
        self.fixups[fixup_pos.0].1 = self.buf.as_ptr() as u64 + self.buf.len() as u64;
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

    pub fn write_fixups(&mut self) {
        for &(fixup, value) in self.fixups.iter().chain(self.constants.iter()) {
            let offset = self.buf.len() - fixup - 4;
            self.buf.write_u64::<LittleEndian>(value).unwrap();
            (&mut self.buf[fixup .. fixup + 4]).write_u32::<LittleEndian>(offset as u32).unwrap();
        }
        self.align(16);
    }

    pub fn write<Cb: FnOnce(*mut u8)>(&mut self,
                                      heap: &mut ExecutableHeap,
                                      extra_len: usize,
                                      write_target: Cb
                                     ) -> *const u8
    {
        let data = heap.allocate(self.buf.len() + extra_len);
        let diff = (data as usize).wrapping_sub(self.buf.as_ptr() as usize);
        for &(fixup, value) in self.fixups.iter() {
            let value_pos = fixup + 4 +
                (&self.buf[fixup .. fixup + 4]).read_u32::<LittleEndian>().unwrap() as usize;
            let value = value.wrapping_add(diff as u64);
            (&mut self.buf[value_pos .. value_pos + 8]).write_u64::<LittleEndian>(value).unwrap();
        }
        unsafe {
            ptr::copy_nonoverlapping(self.buf.as_ptr(), data, self.buf.len());
            write_target(data.offset(self.buf.len() as isize));
        }
        data
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
                let offset = (pos as i32 + self.stack_offset + 1) * 8;
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
        self.stack_offset += 1;
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
                let offset = (from as i32 + self.stack_offset + 1) * 8;
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
                self.buf.write(&[0xff, 0x15]).unwrap();
                self.constants.push((self.buf.len(), dest));
                self.buf.write_u32::<LittleEndian>(0).unwrap();
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
}

unsafe fn copy_instructions(to: *mut u8, from: *const u8, min_len: usize) -> usize {
    let len = ins_len(from, min_len);
    ::std::ptr::copy_nonoverlapping(from, to, len);
    len
}

pub unsafe fn ins_len(code: *const u8, min_len: usize) -> usize {
    let mut len = 0;
    while len < min_len {
        len += single_ins_len(code.offset(len as isize), false);
        println!("@ {:X} len {:x}", *code.offset(len as isize), len);
    }
    len
}

unsafe fn single_ins_len(code: *const u8, size_override: bool) -> usize {
    let imm32_16 = if size_override { 2 } else { 4 };
    match *code.offset(0) {
        // Prefixes
        0x66 => 1 + single_ins_len(code.offset(1), true),
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 |
            0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40 ... 0x4f => 1 + single_ins_len(code.offset(1), size_override),
        0x50 ... 0x62 => 1,
        // Invalid
        0x06 | 0x07 | 0x0e | 0x16 | 0x17 | 0x1e | 0x1f | 0x27 | 0x2f | 0x37 => 1,
        0x82 | 0xc4 | 0xc5 | 0xd4 ... 0xd6 | 0xea => 1,
        // Arithmetic
        0x00 ... 0x03 | 0x08 ... 0x0b | 0x10 ... 0x13 | 0x18 ... 0x1b |
            0x20 ... 0x23 | 0x28 ... 0x2b | 0x30 ... 0x33 | 0x38 ... 0x3b => sib_ins_len(code),
        0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c => 2,
        0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d => 5,
        0x68 => imm32_16 + 1,
        0x69 => imm32_16 + sib_ins_len(code),
        0x6a => 2,
        0x6b => 1 + sib_ins_len(code),
        // I/O
        0x6c ... 0x6f => 1,
        // Short jumps
        0x70 ... 0x7f => 2,
        0x80 | 0x83 => 1 + sib_ins_len(code),
        0x81 => imm32_16 + sib_ins_len(code),
        0x84 ... 0x8f => sib_ins_len(code),
        // Xchg eax, reg + misc
        0x90 ... 0x9f | 0xa4 ... 0xa7 | 0xaa ... 0xaf => 1,
        0xa0 ... 0xa3 => 9,
        0xa8 => 2,
        0xa9 => imm32_16 + 1,
        // Mov reg, imm
        0xb0 ... 0xb7 => 2,
        0xb8 ... 0xbf => imm32_16 + 1,
        0xc0 | 0xc1 | 0xc6 => 1 + sib_ins_len(code),
        0xc7 => imm32_16 + sib_ins_len(code),
        // Ret
        0xc2 | 0xca => 3,
        0xc3 | 0xcb => 1,
        // Enter, leave
        0xc8 => 4,
        0xc9 => 1,
        // Int, iret
        0xcc | 0xce | 0xcf | 0xf1 | 0xf4 | 0xf5 | 0xf8 ... 0xfd => 1,
        0xcd => 2,
        // Bit manip
        0xd0 ... 0xd3 => sib_ins_len(code),
        0xd7 => 1,
        // Fpu
        0xd8 ... 0xdf => sib_ins_len(code),
        // Loop, in, out
        0xe0 ... 0xe7 => 2,
        0xec ... 0xef => 1,
        // Call, jump
        0xe8 | 0xe9 => 5,
        0xeb => 2,
        0xf6 => 1 + sib_ins_len(code),
        0xf7 => imm32_16 + sib_ins_len(code),
        0xfe | 0xff => sib_ins_len(code),
        0xf | _ => unimplemented!(),
    }
}

unsafe fn sib_ins_len(ins: *const u8) -> usize {
    let sib = if (*ins.offset(1) & 0x7) == 0x4 { 1 } else { 0 };
    match (*ins.offset(1) & 0xc0) >> 6 {
        0 => if (*ins.offset(1) & 0x7) == 0x5 { 6 + sib } else { 2 + sib },
        1 => 3 + sib,
        2 => 6 + sib,
        _ => 2, // No sib
    }
}

#[test]
fn test_ins_length() {
    fn check_array(input: &[u8]) {
        unsafe { assert_eq!(single_ins_len(input.as_ptr(), false), input.len()); }
    }
    check_array(&[0x49, 0x8B, 0xCE]);
    check_array(&[0xE8, 0x00, 0x8F, 0x04, 0x00]);
    check_array(&[0x48, 0x8B, 0x95, 0x00, 0x01, 0x00, 0x00]);
    check_array(&[0x49, 0x8B, 0xCE]);
    check_array(&[0xE8, 0xBD, 0xFA, 0xFF, 0xFF]);
    check_array(&[0x41, 0x8B, 0xC6]);
    check_array(&[0x2B, 0xC7]);
    check_array(&[0x89, 0x47, 0x10]);
    check_array(&[0x44, 0x3B, 0xE1]);
    check_array(&[0x41, 0x8B, 0xC4]);
    check_array(&[0x4C, 0x03, 0xF0]);
    check_array(&[0x33, 0xD2]);
    check_array(&[0x41, 0xBC, 0x01, 0x00, 0x00, 0x00]);
    check_array(&[0x40, 0xF6, 0xC6, 0x04]);
    check_array(&[0x44, 0x8B, 0x7D, 0xB8]);
    check_array(&[0x48, 0x8B, 0x55, 0x90]);
    check_array(&[0x49, 0x8B, 0xCE]);
    check_array(&[0x45, 0x8B, 0xC7]);
    check_array(&[0xE8, 0xB0, 0x8E, 0x04, 0x00]);
    check_array(&[0x8B, 0x5D, 0xC8]);
    check_array(&[0x44, 0x3B, 0xFB]);
    check_array(&[0x41, 0x8B, 0xC6]);
    check_array(&[0x45, 0x33, 0xFF]);
    check_array(&[0x4C, 0x03, 0xF3]);
    check_array(&[0x2B, 0xC7]);
    check_array(&[0x89, 0x47, 0x04]);
    check_array(&[0x44, 0x38, 0x7C, 0x24, 0x68]);
    check_array(&[0x75, 0x10]);
    check_array(&[0x49, 0x8B, 0x45, 0x00]);
    check_array(&[0x66, 0x41, 0x23, 0xCC]);
    check_array(&[0x66, 0x09, 0x4F, 0x02]);
    check_array(&[0x8B, 0x75, 0x88]);
    check_array(&[0x48, 0x8B, 0x55, 0x98]);
    check_array(&[0x49, 0x8B, 0xCE]);
    check_array(&[0x44, 0x8B, 0xC6]);
    check_array(&[0xE8, 0x6D, 0x8E, 0x04, 0x00]);
    check_array(&[0x8B, 0x44, 0x24, 0x64]);
    check_array(&[0x3B, 0xF0]);
    check_array(&[0x44, 0x2B, 0xF7]);
    check_array(&[0x44, 0x89, 0x77, 0x08]);
    check_array(&[0x44, 0x38, 0x7C, 0x24, 0x58]);
    check_array(&[0x75, 0x10]);
    check_array(&[0x49, 0x8B, 0x45, 0x00]);
    check_array(&[0x66, 0x83, 0xE1, 0x02]);
    check_array(&[0x66, 0x09, 0x4F, 0x02]);
    check_array(&[0x4C, 0x8B, 0x65, 0xE8]);
    check_array(&[0x4D, 0x8B, 0x45, 0x00]);
    check_array(&[0x33, 0xD2]);
    check_array(&[0x49, 0x8B, 0xCC]);
    check_array(&[0xE8, 0xA1, 0xA1, 0xFE, 0xFF]);
    check_array(&[0x33, 0xD2]);
    check_array(&[0x49, 0x89, 0x7D, 0x00]);
    check_array(&[0x8B, 0xDA]);
    check_array(&[0x4C, 0x8B, 0x7C, 0x24, 0x70]);
    check_array(&[0x48, 0x8B, 0x7C, 0x24, 0x78]);
    check_array(&[0x38, 0x54, 0x24, 0x69]);
    check_array(&[0x4D, 0x85, 0xFF]);
    check_array(&[0x48, 0x85, 0xFF]);
    check_array(&[0x4C, 0x8B, 0x45, 0xE0]);
    check_array(&[0x4D, 0x85, 0xC0]);
    check_array(&[0x4C, 0x8B, 0x45, 0xD8]);
    check_array(&[0x4D, 0x85, 0xC0]);
    check_array(&[0x48, 0x8B, 0x45, 0xB0]);
    check_array(&[0x48, 0x85, 0xC0]);
    check_array(&[0x74, 0x0A]);
    check_array(&[0x38, 0x54, 0x24, 0x55]);
    check_array(&[0x38, 0x54, 0x24, 0x57]);
    check_array(&[0x8B, 0xC3]);
    check_array(&[0x48, 0x8B, 0x8D, 0x88, 0x00, 0x00, 0x00]);
    check_array(&[0x48, 0x33, 0xCC]);
    check_array(&[0xE8, 0x3B, 0x65, 0x03, 0x00]);
    check_array(&[0x48, 0xc1, 0xe8, 0x21]);
}
