use std::{mem, ptr};
use std::io::Write;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use smallvec::SmallVec;

pub use win_common::*;

pub fn nop() -> u8 {
    0x90
}

#[inline]
pub unsafe fn write_call(from: *mut u8, to: *const u8) -> *mut u8 {
    *from = 0xe8;
    *(from.offset(1) as *mut usize) = (to as usize).wrapping_sub(from as usize).wrapping_sub(5);
    from.offset(5)
}

#[inline]
pub unsafe fn write_jump(from: *mut u8, to: *const u8) -> *mut u8 {
    *from = 0xe9;
    *(from.offset(1) as *mut usize) = (to as usize).wrapping_sub(from as usize).wrapping_sub(5);
    from.offset(5)
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
        buffer.push(AsmValue::Undecided);
        let out_wrapper_pos = buffer.fixup_position();
        buffer.push(AsmValue::Undecided);
        for val in self.args.iter().rev() {
            buffer.push(AsmValue::from_loc(val));
        }
        buffer.call(AsmValue::Constant(rust_in_wrapper as u32));
        buffer.stack_add((self.args.len() + 2) * 4);
        buffer.ret(if self.stdcall { stack_args.len() * 4 } else { 0 });

        buffer.reset_stack_offset();
        buffer.fixup_to_position(out_wrapper_pos);
        for (pos, val) in self.args
                .iter()
                .enumerate()
                .filter_map(|(pos, x)| x.reg_to_opt().map(|x| (pos, x))) {
            buffer.mov(AsmValue::Register(val), AsmValue::Stack(pos as i16));
        }
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
            buffer.push(AsmValue::Stack(pos as i16))
        }
        if let Some(s) = stack_args.first() {
            buffer.stack_sub(s.1 as usize * 4);
        }
        if !self.fnptr_hook {
            // Push return address manually
            unsafe {
                let len = copy_instruction_length(self.orig, 5);
                let ret_address = buffer.fixup_position();
                buffer.push(AsmValue::Undecided);
                buffer.copy_instructions(self.orig, len);
                buffer.jump(AsmValue::Constant(self.orig as u32 + len as u32));
                buffer.fixup_to_position(ret_address);
            }
        } else {
            buffer.call(AsmValue::Constant(self.orig as u32));
        };
        buffer.stack_add(if self.stdcall { 0 } else {
            stack_args.last().map(|x| (x.1 + 1) as usize * 4).unwrap_or(0)
        });
        buffer.ret(0);
        buffer.align(16);
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
    fixups: SmallVec<[usize; 8]>,
    relative_fixups: SmallVec<[usize; 8]>,
    stack_offset: i32,
}

pub struct AsmFixupPos(usize);

impl AssemblerBuf {
    pub fn new() -> AssemblerBuf {
        AssemblerBuf {
            buf: Vec::with_capacity(128),
            fixups: SmallVec::new(),
            relative_fixups: SmallVec::new(),
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
        let off = self.fixups[fixup_pos.0];
        let val = self.buf.as_ptr() as u32 + self.buf.len() as u32;
        (&mut self.buf[off .. off + 4]).write_u32::<LittleEndian>(val).unwrap();
    }

    pub fn align(&mut self, amount: usize) {
        while self.buf.len() % amount != 0 {
            self.buf.push(0xcc);
        }
    }

    pub unsafe fn copy_instructions(&mut self, source: *const u8, amt: usize) {
        self.buf.reserve(amt);
        copy_instructions(source, self.buf.as_mut_ptr().offset(self.buf.len() as isize), amt);
        let new_len = self.buf.len() + amt;
        self.buf.set_len(new_len);
    }

    pub fn write<Cb: FnOnce(*mut u8)>(&mut self,
                                      heap: &mut ExecutableHeap,
                                      extra_len: usize,
                                      write_target: Cb
                                     ) -> *const u8
    {
        let data = heap.allocate(self.buf.len() + extra_len);
        let diff = (data as usize).wrapping_sub(self.buf.as_ptr() as usize);
        for &fixup in self.fixups.iter() {
            let prev = (&self.buf[fixup .. fixup + 4]).read_u32::<LittleEndian>().unwrap();
            (&mut self.buf[fixup .. fixup + 4]).write_u32::<LittleEndian>(prev.wrapping_add(diff as u32)).unwrap();
        }
        for &fixup in self.relative_fixups.iter() {
            let prev = (&self.buf[fixup .. fixup + 4]).read_u32::<LittleEndian>().unwrap();
            (&mut self.buf[fixup .. fixup + 4]).write_u32::<LittleEndian>(prev.wrapping_sub(diff as u32)).unwrap();
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
                let offset = (pos as i32 + self.stack_offset + 1) * 4;
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
                    self.buf.write_u8(0x89).unwrap();
                    self.buf.write_u8(0xc0 + from * 8 + to).unwrap();
                }
            }
            (AsmValue::Register(to), AsmValue::Stack(from)) => {
                let offset = (from as i32 + self.stack_offset + 1) * 4;
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
                self.buf.write_u8(0xe9).unwrap();
                self.relative_fixups.push(self.buf.len());
                let current_pos = self.buf.as_ptr() as u32 + self.buf.len() as u32;
                let value = dest.wrapping_sub((current_pos).wrapping_add(4));
                self.buf.write_u32::<LittleEndian>(value).unwrap();
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
                self.buf.write_u8(0xe8).unwrap();
                self.relative_fixups.push(self.buf.len());
                let current_pos = self.buf.as_ptr() as u32 + self.buf.len() as u32;
                let value = dest.wrapping_sub((current_pos).wrapping_add(4));
                self.buf.write_u32::<LittleEndian>(value).unwrap();
            }
            AsmValue::Register(dest) => {
                self.buf.write(&[0xff, 0xd0 + dest]).unwrap();
            }
            _ => unimplemented!(),
        }
    }
}

unsafe fn x86_sib_ins_size(ins: *const u8) -> usize {
    let sib = if (*ins.offset(1) & 0x7) == 0x4 { 1 } else { 0 };
    match (*ins.offset(1) & 0xc0) >> 6 {
        0 => if (*ins.offset(1) & 0x7) == 0x5 { 6 + sib } else { 2 + sib },
        1 => 3 + sib,
        2 => 6 + sib,
        _ => 2, // No sib
    }
}

unsafe fn x86_ins_size(ins: *const u8) -> usize {
    match *ins {
        0x50 ... 0x61 | 0x90 => 1,
        0x68 => 5,
        0x00 ... 0x03 | 0x84 ... 0x8f | 0xff => x86_sib_ins_size(ins),
        0x83 | 0xc0 | 0xc1 | 0xc6 => x86_sib_ins_size(ins) + 1,
        0x81 => x86_sib_ins_size(ins) + 4,
        0xa1 | 0xb9 | 0xba | 0xe8 | 0xe9 => 5,
        n => panic!("Unimpl ins size 0x{:x}", n),
    }
}

pub unsafe fn copy_instruction_length(ins: *const u8, min_length: usize) -> usize {
    let mut pos = 0;
    while pos < min_length {
        pos += x86_ins_size(ins.offset(pos as isize));
    }
    pos
}

unsafe fn copy_instructions(mut src: *const u8, mut dst: *mut u8, len: usize) {
    let mut len = len as isize;
    while len > 0 {
        let ins_len = x86_ins_size(src) as isize;
        // Relative jumps need to be handled differently
        match *src {
            0xe8 | 0xe9 => {
                assert!(ins_len == 5);
                ptr::copy_nonoverlapping(src, dst, 5);
                let diff = mem::transmute::<_, usize>(dst).overflowing_sub(mem::transmute(src)).0;
                let jump_offset: *mut usize = mem::transmute(dst.offset(1));
                *jump_offset = (*jump_offset).overflowing_sub(diff).0;

            }
            _ => ptr::copy_nonoverlapping(src, dst, ins_len as usize),
        }
        src = src.offset(ins_len);
        dst = dst.offset(ins_len);
        len -= ins_len;
    }
}

#[test]
fn test_x86_ins_size() {
    let inss = vec![vec![0x89, 0x45, 0xfc], vec![0xc6, 0x05, 0xfb, 0x01, 0xe8, 0xdc, 0xfa],
    vec![0xc6, 0x45, 0xfb, 0x01], vec![0x55], vec![0x60], vec![0x8b, 0xec], vec![0x83, 0xec, 0x0c]];
    unsafe {
        for ins in inss {
            assert_eq!(ins.len(), x86_ins_size(ins.as_ptr()));
        }
    }
}

#[test]
fn test_x86_copy_ins() {
    let ins1 = vec![0x89, 0x45, 0xfc, 0xff];
    let mut ins2 = vec![0xe8, 0x50, 0x60, 0x70, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff];
    unsafe {
        let mut tgt = vec![0; 5];
        copy_instructions(ins1.as_ptr(), tgt.as_mut_ptr(), 1);
        assert_eq!(tgt, vec![0x89, 0x45, 0xfc, 0x00, 0x00]);
        copy_instructions(ins2.as_ptr(), ins2.as_mut_ptr().offset(5), 1);
        assert_eq!(ins2, vec![0xe8, 0x50, 0x60, 0x70, 0x80, 0xe8, 0x4b, 0x60, 0x70, 0x80]);
    }
}
