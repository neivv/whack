
pub use win_common::*;

#[inline]
unsafe fn write_push(out: *mut u8, reg_id: u8, offset: u32) -> *mut u8 {
    match reg_id {
        0...7 => {
            *out = 0x50 + reg_id;
            out.offset(1)
        }
        8...15 => {
            *out = 0x41;
            *out.offset(1) = 0x50 + reg_id - 8;
            out.offset(2)
        }
        _ => {
            if offset * 8 < 0x10 {
                *out.offset(0) = 0xff;
                *out.offset(1) = 0x74;
                *out.offset(2) = 0xe4;
                *out.offset(3) = offset as u8 * 8;
                out.offset(4)
            } else {
                *out.offset(0) = 0xff;
                *out.offset(1) = 0xb4;
                *out.offset(2) = 0xe4;
                *(out.offset(3) as *mut u32) = offset as u32 * 8;
                out.offset(7)
            }
        }
    }
}

#[inline]
unsafe fn write_mov(out: *mut u8, to: u8, from: u8, stack_off: u32) -> *mut u8 {
    match (to, from) {
        (x, y) if x == y => out,
        (to, from) if from == !0 => {
            *out = 0x67;
            *out.offset(1) = if to < 8 { 0x48 } else { 0x4c };
            *out.offset(2) = 0x8b;
            if stack_off < 0x10 {
                *out.offset(3) = 0x44 + 8 * (to & 0x7);
                *out.offset(4) = 0x24;
                *out.offset(5) = stack_off as u8;
                out.offset(6)
            } else {
                *out.offset(3) = 0x84 + 8 * (to & 0x7);
                *out.offset(4) = 0x24;
                *(out.offset(5) as *mut u32) = stack_off as u32;
                out.offset(9)
            }
        }
        (to, from) => {
            *out = 0x48 + if to < 8 { 0 } else { 1 } + if from < 8 { 0 } else { 4 };
            *out.offset(1) = 0x89;
            *out.offset(2) = 0xc0 + 8 * (from & 0x7) + (to & 0x7);
            out.offset(3)
        }
    }
}

#[inline]
pub unsafe fn write_in_wrapper_arg(out: *mut u8, reg_id: u8, arg_num: u32, pos: u32, stack_arg_num: u32) -> (*mut u8, u32) {
    match arg_num {
        0 => (write_mov(out, reg_id!(rcx), reg_id, pos + stack_arg_num), pos + 0),
        1 => (write_mov(out, reg_id!(rdx), reg_id, pos + stack_arg_num), pos + 0),
        2 => (write_mov(out, reg_id!(r8), reg_id, pos + stack_arg_num), pos + 0),
        3 => (write_mov(out, reg_id!(r9), reg_id, pos + stack_arg_num), pos + 0),
        _ => (write_push(out, reg_id, pos + stack_arg_num), pos + 1),
    }
}

#[inline]
pub unsafe fn write_in_wrapper_const_args(out: *mut u8, arg_num: u32, pos: u32,
                                          free_reg: u8, out_wrapper: usize, target: usize)
    -> (*mut u8, u32) {
    let (out, pos) = write_in_wrapper_const_arg(out, arg_num + 1, pos, free_reg, target);
    write_in_wrapper_const_arg(out, arg_num, pos, free_reg, out_wrapper)
}

#[inline]
unsafe fn write_in_wrapper_const_arg(out: *mut u8, arg_num: u32, pos: u32, free_reg: u8, value: usize)
    -> (*mut u8, u32) {
    match arg_num {
        0 => (write_const_mov(out, reg_id!(rcx), value), pos),
        1 => (write_const_mov(out, reg_id!(rdx), value), pos),
        2 => (write_const_mov(out, reg_id!(r8), value), pos),
        3 => (write_const_mov(out, reg_id!(r9), value), pos),
        _ => (write_const_push(out, free_reg, value), pos + 1),
    }
}

#[inline]
unsafe fn const_mov_size() -> usize {
    10
}

#[inline]
unsafe fn write_const_mov(out: *mut u8, reg: u8, value: usize) -> *mut u8 {
    *out = if reg < 8 { 0x48 } else { 0x49 };
    *out.offset(1) = 0xb8 + (reg & 0x7);
    *(out.offset(2) as *mut usize) = value;
    out.offset(10)
}

#[inline]
pub unsafe fn const_push_size(clobber: u8) -> usize {
    match clobber {
        0...7 => 1 + const_mov_size(),
        _ => 2 + const_mov_size(),
    }
}

#[inline]
unsafe fn write_const_push(out: *mut u8, clobber: u8, value: usize) -> *mut u8 {
    let out = write_const_mov(out, clobber, value);
    match clobber {
        0...7 => {
            *out.offset(0) = 0x50 + clobber;
            out.offset(1)
        }
        _ => {
            *out.offset(0) = 0x41;
            *out.offset(1) = 0x50 + clobber;
            out.offset(2)
        }
    }
}

#[inline]
pub unsafe fn write_call(out: *mut u8, clobber: u8, target: usize) -> *mut u8 {
    let out = write_const_mov(out, clobber, target);
    if clobber < 8 {
        *out.offset(0) = 0xff;
        *out.offset(1) = 0xd0 + clobber;
        out.offset(2)
    } else {
        *out.offset(0) = 0x41;
        *out.offset(1) = 0xff;
        *out.offset(2) = 0xd0 + (clobber & 0x7);
        out.offset(3)
    }
}

#[inline]
pub unsafe fn write_jump(out: *mut u8, clobber: u8, target: *const u8) -> *mut u8 {
    let out = write_const_mov(out, clobber, target as usize);
    if clobber < 8 {
        *out.offset(0) = 0xff;
        *out.offset(1) = 0xe0 + clobber;
        out.offset(2)
    } else {
        *out.offset(0) = 0x41;
        *out.offset(1) = 0xff;
        *out.offset(2) = 0xe0 + (clobber & 0x7);
        out.offset(3)
    }
}

#[inline]
pub fn out_wrapper_arg_size(amt: usize, reg_id: u8, arg_num: u32, pos: u32) -> (usize, u32) {
    if reg_id < 16 {
        (amt + match arg_num {
            0 => mov_size(reg_id, reg_id!(rcx), pos + arg_num),
            1 => mov_size(reg_id, reg_id!(rcx), pos + arg_num),
            2 => mov_size(reg_id, reg_id!(rcx), pos + arg_num),
            3 => mov_size(reg_id, reg_id!(rcx), pos + arg_num),
            _ => mov_size(reg_id, !0, pos + arg_num),
        }, pos)
    } else {
        (amt + match arg_num {
            0 => push_size(reg_id!(rcx), pos + arg_num),
            1 => push_size(reg_id!(rdx), pos + arg_num),
            2 => push_size(reg_id!(r8), pos + arg_num),
            3 => push_size(reg_id!(r9), pos + arg_num),
            _ => push_size(!0, pos + arg_num),
        }, pos + 1)
    }
}

#[inline]
fn mov_size(to: u8, from: u8, stack_off: u32) -> usize {
    assert!(to != !0 || from != !0);
    match (to, from) {
        (0xff, _) | (_, 0xff) => if stack_off < 0x10 { 5 } else { 8 },
        (_, _) => 3,
    }
}

#[inline]
pub fn push_size(loc: u8, stack_off: u32) -> usize {
    match loc {
        0...7 => 1,
        8...15 => 2,
        _ => if stack_off < 0x10 { 5 } else { 8 },
    }
}

#[inline]
pub unsafe fn write_out_call(out: *mut u8, orig_jmp_reg: u8, orig: *const u8, stack_off: u32) -> *mut u8 {
    // sub rsp, 20
    *(out as *mut u32) = 0x20ec8348;
    let out = out.offset(4);
    let len = ins_len(orig, if orig_jmp_reg < 8 { 12 } else { 13 });
    let ret_push_len = const_push_size(orig_jmp_reg);
    let out = write_const_push(out, orig_jmp_reg, out as usize + ret_push_len + len + 6 + 8);
    copy_instructions(out, orig, if orig_jmp_reg < 8 { 12 } else { 13 });
    let out = out.offset(len as isize);
    // jmp [rip]
    *out.offset(0) = 0xff;
    *out.offset(1) = 0x25;
    *out.offset(2) = 0x00;
    *out.offset(3) = 0x00;
    *out.offset(4) = 0x00;
    *out.offset(5) = 0x00;
    // ([rip])
    *(out.offset(6) as *mut usize) = orig as usize + len;
    let out = out.offset(6 + 8);
    // Pop arguments
    let out = write_add(out, reg_id!(rsp), (stack_off + 4 - 1) * 8);
    // Return
    *out = 0xc3;
    out.offset(1)
}

#[inline]
unsafe fn write_add(out: *mut u8, reg_id: u8, value: u32) -> *mut u8 {
    if value < 0x80 {
        *out.offset(0) = if reg_id < 8 { 0x48 } else { 0x49 };
        *out.offset(1) = 0x83;
        *out.offset(2) = 0xc0 + (reg_id & 0x7);
        *out.offset(3) = value as u8;
        out.offset(4)
    } else {
        *out.offset(0) = if reg_id < 8 { 0x48 } else { 0x49 };
        *out.offset(1) = 0x81;
        *out.offset(2) = 0xc0 + (reg_id & 0x7);
        *(out.offset(3) as *mut u32) = value;
        out.offset(7)
    }
}

#[inline]
pub unsafe fn write_out_argument(out: *mut u8, pos: u32, loc: u8, arg_num: u32) -> (*mut u8, u32) {
    if loc < 16 {
        (match arg_num {
            0 => write_mov(out, loc, reg_id!(rcx), pos + arg_num),
            1 => write_mov(out, loc, reg_id!(rdx), pos + arg_num),
            2 => write_mov(out, loc, reg_id!(r8), pos + arg_num),
            3 => write_mov(out, loc, reg_id!(r9), pos + arg_num),
            _ => write_mov(out, loc, !0, pos + arg_num),
        }, pos)
    } else {
        (match arg_num {
            0 => write_push(out, reg_id!(rcx), pos + arg_num),
            1 => write_push(out, reg_id!(rdx), pos + arg_num),
            2 => write_push(out, reg_id!(r8), pos + arg_num),
            3 => write_push(out, reg_id!(r9), pos + arg_num),
            _ => write_push(out, !0, pos + arg_num),
        }, pos + 1)
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
        0xc0 | 0xc6 => 1 + sib_ins_len(code),
        0xc1 | 0xc7 => imm32_16 + sib_ins_len(code),
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
}
