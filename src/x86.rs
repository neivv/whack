use std::{mem, ptr};

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

#[inline]
unsafe fn write_add(out: *mut u8, reg_id: u8, value: u32) -> *mut u8 {
    if value < 0x80 {
        *out.offset(0) = 0x83;
        *out.offset(1) = 0xc0 + reg_id;
        *out.offset(2) = value as u8;
        out.offset(3)
    } else {
        *out.offset(0) = 0x81;
        *out.offset(1) = 0xc0 + reg_id;
        *(out.offset(2) as *mut u32) = value;
        out.offset(6)
    }
}

#[inline]
pub unsafe fn write_in_wrapper_arg(out: *mut u8, reg: u8, pos: u32, stack_num: u32) -> (*mut u8, u32) {
    (write_push(out, reg, pos + stack_num), pos + 1)
}

#[inline]
unsafe fn write_mov(out: *mut u8, to: u8, from: u8, stack_off: u32) -> *mut u8 {
    match (to, from) {
        (x, y) if x == y => out,
        (to, from) if from == !0 => {
            *out.offset(0) = 0x8b;
            if stack_off < 0x20 {
                *out.offset(1) = 0x44 + 8 * to;
                *out.offset(2) = 0x24;
                *out.offset(3) = (stack_off * 4) as u8;
                out.offset(4)
            } else {
                *out.offset(1) = 0x84 + 8 * to & 0x7;
                *out.offset(2) = 0x24;
                *(out.offset(3) as *mut u32) = stack_off * 4;
                out.offset(7)
            }
        }
        (to, from) => {
            *out.offset(0) = 0x89;
            *out.offset(1) = 0xc0 + 8 * from + to;
            out.offset(2)
        }
    }
}

#[inline]
unsafe fn write_push(out: *mut u8, reg_id: u8, offset: u32) -> *mut u8 {
    match reg_id {
        0...7 => {
            *out = 0x50 + reg_id;
            out.offset(1)
        }
        _ => {
            if offset * 4 < 0x20 {
                *out.offset(0) = 0xff;
                *out.offset(1) = 0x74;
                *out.offset(2) = 0xe4;
                *out.offset(3) = offset as u8 * 4;
                out.offset(4)
            } else {
                *out.offset(0) = 0xff;
                *out.offset(1) = 0xb4;
                *out.offset(2) = 0xe4;
                *(out.offset(3) as *mut u32) = offset as u32 * 4;
                out.offset(7)
            }
        }
    }
}

#[inline]
pub unsafe fn push_const(out: *mut u8, value: u32) -> *mut u8 {
    *out = 0x68;
    *(out.offset(1) as *mut u32) = value;
    out.offset(5)
}

#[inline]
pub unsafe fn write_out_call(out: *mut u8, orig: *const u8, stack_off: u32, stdcall: bool, copy_from_dest: bool) -> *mut u8 {
    let mut out = if copy_from_dest {
        // Push return address manually
        let len = copy_instruction_length(orig, 5);
        let out = push_const(out, 5 + out as u32 + len as u32 + 5);
        copy_instructions(orig, out, 5);
        let out = out.offset(len as isize);
        let dest = orig.offset(len as isize);
        write_jump(out, dest)
    } else {
        write_call(out, orig)
    };
    if !stdcall {
        out = write_add(out, reg_id!(esp), stack_off * 4);
    }
    *out = 0xc3;
    out.offset(1)
}

#[inline]
pub unsafe fn write_out_argument(out: *mut u8, pos: u32, loc: u8, arg_num: u32) -> (*mut u8, u32) {
    if loc < 8 {
        (write_mov(out, loc, !0, pos + arg_num), pos)
    } else {
        (write_push(out, !0, pos + arg_num), pos + 1)
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

unsafe fn copy_instructions(mut src: *const u8, mut dst: *mut u8, mut len: isize) {
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
