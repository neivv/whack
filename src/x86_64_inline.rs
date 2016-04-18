
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
unsafe fn write_const_mov(out: *mut u8, reg: u8, value: usize) -> *mut u8 {
    *out = if reg < 8 { 0x48 } else { 0x49 };
    *out.offset(1) = 0xb8 + (reg & 0x7);
    *(out.offset(2) as *mut usize) = value;
    out.offset(10)
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
pub unsafe fn write_jump(out: *mut u8, clobber: u8, target: usize) -> *mut u8 {
    let out = write_const_mov(out, clobber, target);
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
