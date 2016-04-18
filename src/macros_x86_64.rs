
#[macro_export]
#[doc(hidden)]
macro_rules! reg_id {
    (rax) => { 0 };
    (rcx) => { 1 };
    (rdx) => { 2 };
    (rbx) => { 3 };
    (rsp) => { 4 };
    (rbp) => { 5 };
    (rsi) => { 6 };
    (rdi) => { 7 };
    (r8) => { 8 };
    (r9) => { 9 };
    (r10) => { 10 };
    (r11) => { 11 };
    (r12) => { 12 };
    (r13) => { 13 };
    (r14) => { 14 };
    (r15) => { 15 };
}

#[macro_export]
#[doc(hidden)]
macro_rules! push_const_size {
    ($reg:ident) => {{
        let x = reg_id!($reg);
        if x < 8 { 11 } else { 12 }
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! call_const_size {
    ($reg:ident) => {{
        let x = reg_id!($reg);
        if x < 8 { 12 } else { 13 }
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_named {
    ($is_pub:ident ~ system, $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        impl_named!(rax, $is_pub ~ $ord, $name, $ret, $([$an @ $aloc: $aty])*);
    };
    ($freereg:ident, $is_pub:ident ~ $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        maybe_pub_struct!($is_pub, $name);
        impl $name {
            // caller -> assembly wrap -> in_wrap -> hook.
            // If the hook wishes to call original function,
            // then it'll go hook -> out_wrap -> assembly -> original.
            // Orig is pointer to the assembly wrapper which calls original function,
            // Real is pointer to the fat pointer of hook Fn(...).
            extern fn in_wrap($($an: $aty),*,
                              orig: extern fn($($aty),*) -> $ret,
                              real: *const *const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret
                             ) -> $ret
            {
                let real: &Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret = unsafe { &**real };
                real($($an,)* &|$($an),*| $name::out_wrap($($an,)* orig))
            }

            extern fn out_wrap($($an: $aty,)* orig: extern fn($($aty),*) -> $ret) -> $ret {
                orig($($an),*)
            }

            fn in_asm_size() -> usize {
                let needed = {
                    // Arg pushes
                    in_wrapper_args_size!($freereg, 1, 0, 0, [$($aloc),*]).0 +
                    // Call + pop + ret
                    call_const_size!($freereg) + in_wrapper_pop_size!(2 $(,$aty)*) + 1
                };
                // Round to 16
                ((needed - 1) | 0xf) + 1
            }

            fn out_asm_size() -> usize {
                // Arg pushes + call + ret
                let needed = call_const_size!(rax);
                // Round to 16
                ((needed - 1) | 0xf) + 1
            }
        }
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static> $crate::ExportHook<T> for $name {
            fn wrapper_size() -> usize {
                $name::in_asm_size() + $name::out_asm_size() + ::std::mem::size_of::<T>() +
                    ::std::mem::size_of::<*const Fn($($aty,)* &Fn($($aty),*) -> $ret)>()
            }

            fn default_export() -> $crate::Export<'static> {
                if $ord as i32 == -1 {
                    let name = stringify!($name);
                    $crate::Export::Name(name.as_bytes())
                } else {
                    $crate::Export::Ordinal($ord as u16)
                }
            }

            unsafe fn write_wrapper(out: *mut u8, target: T, orig_addr: *const u8) {
                let in_wrap_addr = $name::in_wrap as usize;
                let out_wrapper = out.offset($name::in_asm_size() as isize) as usize;
                let target_addr = out.offset(($name::in_asm_size() + $name::out_asm_size()) as isize) as usize;
                let mut out_pos = out;

                // IN WRAPPER
                // Push args.
                out_pos = write_in_wrapper_args!($freereg, out_pos, 1, 0, 0,
                                                 target_addr, out_wrapper, [$($aty),*], [$($aloc),*]).0;
                // sub rsp, 20
                *(out_pos as *mut u32) = 0x20ec8348;
                out_pos = out_pos.offset(4);
                // Call in_wrap()
                let reg = reg_id!($freereg);
                out_pos = $crate::platform_inline::write_call(out_pos, reg, in_wrap_addr);
                // Pop in_wrapper arguments. Adds 2 for the two pointers.
                out_pos = pop_wrapper_args!(out_pos, 2 $(,$aty)*);
                // Return.
                *out_pos = 0xc3;
                assert!(out_pos as usize <= out_wrapper);
                out_pos = out_wrapper as *mut u8;
                // OUT WRAPPER
                // Just jump to the original code.
                // TODO: Do compilers generate strange calling conventions on 64-bit windows?
                // In wrapper doesn't handle them really either, but it has register order
                // softcoded.
                out_pos = $crate::platform_inline::write_jump(out_pos, reg, orig_addr as usize);

                assert!(out_pos as usize <= target_addr);
                out_pos = target_addr as *mut u8;
                let ptr_size = ::std::mem::size_of::<
                    *const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret >() as isize;
                let target_mem = out_pos.offset(ptr_size) as *mut T;
                ::std::ptr::copy_nonoverlapping(&target, target_mem, 1);
                ::std::mem::forget(target);
                let target_ptr: *const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret = target_mem;
                let ptr_pos = out_pos as *mut *const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret;
                ::std::ptr::copy_nonoverlapping(&target_ptr, ptr_pos, 1);
                ::std::mem::forget(target_ptr);
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! if_stack {
    (stack, $yes:expr, $no:expr) => { $yes };
    ($other:ident, $yes:expr, $no:expr) => { $no };
}

#[macro_export]
#[doc(hidden)]
macro_rules! reg_id_or_stack {
    (stack) => { !0 };
    ($reg:ident) => { reg_id!($reg) };
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_in_wrapper_args {
    ($freereg:ident, $out:expr, $pos:expr, $arg_num:expr, $stack_arg_num:expr, $target:expr, $out_wrapper:expr,
        [$next:ty $(,$aty:ty)*], [$loc:ident $(,$aloc:ident)*]) => {{
        // The reg args also have stack space as well. Doesn't work with exotic calling conventions
        let _next_stack_arg = $stack_arg_num + 1;
        let (out, pos) = write_in_wrapper_args!($freereg, $out, $pos, $arg_num + 1, _next_stack_arg,
                                                $target, $out_wrapper, [$($aty),*], [$($aloc),*]);
        let id = reg_id_or_stack!($loc);
        $crate::platform_inline::write_in_wrapper_arg(out, id, $arg_num, pos, $stack_arg_num)
    }};
    ($freereg:ident, $out:expr, $pos: expr, $arg_num:expr, $stack_arg_num:expr,
     $target:expr, $out_wrap:expr, [], []) => {{
        let reg = reg_id!($freereg);
        $crate::platform_inline::write_in_wrapper_const_args($out, $arg_num, $pos, reg, $out_wrap, $target)
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_args_size {
    // Manually unwrap these to prevent ridiculous macro explosions
    ($freereg:ident, $pos:expr, 0, $stack_arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let _next_stack_arg = $stack_arg_num + 1;
        let (amt, pos) = in_wrapper_args_size!($freereg, $pos, 1, _next_stack_arg, [$($aloc),*]);
        (amt + if_stack!($loc, if pos + $stack_arg_num < 0x10 { 6 } else { 9 }, 10), pos)
    }};
    ($freereg:ident, $pos:expr, 1, $stack_arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let _next_stack_arg = $stack_arg_num + 1;
        let (amt, pos) = in_wrapper_args_size!($freereg, $pos, 2, _next_stack_arg, [$($aloc),*]);
        (amt + if_stack!($loc, if pos + $stack_arg_num < 0x10 { 6 } else { 9 }, 10), pos)
    }};
    ($freereg:ident, $pos:expr, 2, $stack_arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let _next_stack_arg = $stack_arg_num + 1;
        let (amt, pos) = in_wrapper_args_size!($freereg, $pos, 3, _next_stack_arg, [$($aloc),*]);
        (amt + if_stack!($loc, if pos + $stack_arg_num < 0x10 { 6 } else { 9 }, 10), pos)
    }};
    ($freereg:ident, $pos:expr, 3, $stack_arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let _next_stack_arg = $stack_arg_num + 1;
        let (amt, pos) = in_wrapper_args_size!($freereg, $pos, 4, _next_stack_arg, [$($aloc),*]);
        (amt + if_stack!($loc, if pos + $stack_arg_num < 0x10 { 6 } else { 9 }, 10), pos)
    }};
    ($freereg:ident, $pos:expr, $arg_num:expr, $stack_arg_num:expr,
        [$loc:ident $(,$aloc:ident)*]) => {{
        let _next_stack_arg = $stack_arg_num + 1;
        let (amt, pos) = in_wrapper_args_size!($freereg, $pos, $arg_num + 1, _next_stack_arg, [$($aloc),*]);
        (amt + if pos + $stack_arg_num >= 0x10 { 7 } else { 4 }, pos + 1)
    }};
    ($freereg:ident, $pos:expr, 0, $stack_arg_num:expr, []) => {
        (20, $pos)
    };
    ($freereg:ident, $pos:expr, 1, $stack_arg_num:expr, []) => {
        (20, $pos)
    };
    ($freereg:ident, $pos:expr, 2, $stack_arg_num:expr, []) => {
        (20, $pos)
    };
    ($freereg:ident, $pos:expr, 3, $stack_arg_num:expr, []) => {
        (10 + push_const_size!($freereg), $pos + 1)
    };
    ($freereg:ident, $pos:expr, $arg_num:expr, $stack_arg_num:expr, []) => {
        (2 * push_const_size!($freereg), $pos + 2)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! pop_wrapper_args {
    ($out:expr, $pos:expr, $next:ty $(,$aty:ty)*) => {
        pop_wrapper_args!($out, $pos + 1 $(,$aty)*)
    };
    ($out:expr, $pos: expr) => {{
        let out = $out;
        let amt = if $pos < 4 { 4 } else { $pos };
        if amt >= 0x10 {
            *out.offset(0) = 0x48;
            *out.offset(1) = 0x81;
            *out.offset(2) = 0xc4;
            *(out.offset(3) as *mut u32) = amt * 8;
            out.offset(7)
        } else {
            *out.offset(0) = 0x48;
            *out.offset(1) = 0x83;
            *out.offset(2) = 0xc4;
            *out.offset(3) = amt as u8 * 8;
            out.offset(4)
        }
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_pop_size {
    ($pos:expr, $next:ty $(,$aty:ty)*) => {
        in_wrapper_pop_size!($pos + 1 $(,$aty)*)
    };
    ($pos: expr) => {{
        if $pos >= 0x10 { 7 } else { 4 }
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_ret_size {
    ($pos:expr, $next:ty $(,$aty:ty)*) => {
        in_wrapper_ret_size!($pos + 1 $(,$aty)*)
    };
    ($pos:expr) => {
        if $pos == 0 { 1 } else { 3 }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_hook {
    ($is_pub:ident ~ $abi:ident, $ord:expr, $name:ident, $ret:ty, [$([$argty:ty])*]) => {
        // Increase arg name count if needed...
        name_args!($is_pub ~ $abi, $ord, $name, $ret, [], [$($argty,)*], [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10],
                    [rcx, rdx, r8, r9, stack, stack, stack, stack, stack, stack]);
    };
}
