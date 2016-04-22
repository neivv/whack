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
macro_rules! impl_addr_hook {
    ($is_pub:ident, cdecl, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident: $aty:ty])*) =>
    {
        impl_addr_hook!(rax, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc: $aty])*);
    };
    ($freereg:ident, $is_pub:ident, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident: $aty:ty])*) =>
    {
        maybe_pub_struct!($is_pub, $name);
        hook_impl_private!(no, $name, $freereg, $ret, $([$an @ $aloc: $aty])*);
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static> $crate::AddressHook<T> for $name {
            fn address(current_base: usize) -> usize {
                current_base.wrapping_sub($base).wrapping_add($addr)
            }

            hook_wrapper_impl!(no, $name, $freereg, $ret, $([$an @ $aloc: $aty])*);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_import_hook {
    ($is_pub:ident, system, $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        impl_import_hook!(rax, $is_pub, $ord, $name, $ret, $([$an @ $aloc: $aty])*);
    };
    ($freereg:ident, $is_pub:ident, $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        maybe_pub_struct!($is_pub, $name);
        hook_impl_private!(yes, $name, $freereg, $ret, $([$an @ $aloc: $aty])*);
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static> $crate::ExportHook<T> for $name {
            fn default_export() -> $crate::Export<'static> {
                if $ord as i32 == -1 {
                    let name = stringify!($name);
                    $crate::Export::Name(name.as_bytes())
                } else {
                    $crate::Export::Ordinal($ord as u16)
                }
            }

            hook_wrapper_impl!(yes, $name, $freereg, $ret, $([$an @ $aloc: $aty])*);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_impl_private {
    ($fnptr_hook:ident, $name:ident, $freereg:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        impl $name {
            // caller -> assembly wrap -> in_wrap -> hook.
            // If the hook wishes to call original function,
            // then it'll go hook -> out_wrap -> assembly -> original.
            // Orig is pointer to the assembly wrapper which calls original function,
            // Real is pointer to the fat pointer of hook Fn(...).
            extern fn in_wrap($($an: $aty,)*
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

            unsafe fn out_asm_size(_orig: *const u8) -> usize {
                let needed = out_asm_size!($fnptr_hook, $freereg, _orig, 1, 0, [$($aloc),*]).0 as usize;
                // Round to 16
                ((needed - 1) | 0xf) + 1
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! out_asm_size {
    (yes, $freereg:ident, $orig:expr, $arg_num:expr, $pos:expr, [$($aloc:ident),*]) => {
        (call_const_size!($freereg), 0)
    };
    (no, $freereg:ident, $orig:expr, $arg_num:expr, $pos:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let (amt, pos) = out_asm_size!(no, $freereg, $orig, $arg_num + 1, $pos, [$($aloc),*]);
        let loc = reg_id_or_stack!($loc);
        $crate::platform::out_wrapper_arg_size(amt, loc, $arg_num, pos)
    }};
    (no, $freereg:ident, $orig:expr, $arg_num:expr, $pos:expr, []) => {{
        let reg_id = reg_id!($freereg);
        let jmp_size = call_const_size!($freereg);
        let ret_push_size = $crate::platform::const_push_size(reg_id);
        // 6 + 8 for jmp [rip + 6], 4 for sub rsp, 20
        (ret_push_size + 6 + 8 + 4 + $crate::platform::ins_len($orig, jmp_size) + 7 + 1, 0)
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_wrapper_impl {
    ($fnptr_hook:ident, $name:ident, $freereg:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        unsafe fn wrapper_size(orig: *const u8) -> usize {
            $name::in_asm_size() + $name::out_asm_size(orig) + ::std::mem::size_of::<T>() +
                ::std::mem::size_of::<*const Fn($($aty,)* &Fn($($aty),*) -> $ret)>()
        }

        unsafe fn write_wrapper(out: *mut u8, target: T, orig_addr: *mut u8) {
            let in_wrap_addr = $name::in_wrap as usize;
            let out_wrapper = out.offset($name::in_asm_size() as isize) as usize;
            let target_addr = out.offset(($name::in_asm_size() + $name::out_asm_size(orig_addr)) as isize) as usize;
            let mut out_pos = out;

            // IN WRAPPER
            // Push args.
            out_pos = write_in_wrapper_args!($freereg, out_pos, 1, 0, 0,
                                             target_addr, out_wrapper, [$($aloc),*]).0;
            // sub rsp, 20
            *(out_pos as *mut u32) = 0x20ec8348;
            out_pos = out_pos.offset(4);
            // Call in_wrap()
            let reg = reg_id!($freereg);
            out_pos = $crate::platform::write_call(out_pos, reg, in_wrap_addr);
            // Pop in_wrapper arguments. Adds 2 for the two pointers.
            out_pos = pop_wrapper_args!(out_pos, 2 $(,$aty)*);
            // Return.
            *out_pos = 0xc3;
            assert!(out_pos as usize <= out_wrapper);
            out_pos = out_wrapper as *mut u8;
            // OUT WRAPPER
            out_pos = write_out_wrapper!($fnptr_hook, out_pos, reg, orig_addr, 0, [$($aloc),*]);

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

            write_hooking_jump!($fnptr_hook, orig_addr, reg, out);
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_hooking_jump {
    (yes, $src:expr, $clobber:expr, $dest:expr) => {};
    (no, $src:expr, $clobber:expr, $dest:expr) => {
        $crate::platform::write_jump($src, $clobber, $dest)
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
        [$loc:ident $(,$aloc:ident)*]) => {{
        // The reg args also have stack space as well. Doesn't work with exotic calling conventions
        let _next_stack_arg = $stack_arg_num + 1;
        let (out, pos) = write_in_wrapper_args!($freereg, $out, $pos, $arg_num + 1, _next_stack_arg,
                                                $target, $out_wrapper, [$($aloc),*]);
        let id = reg_id_or_stack!($loc);
        $crate::platform::write_in_wrapper_arg(out, id, $arg_num, pos, $stack_arg_num)
    }};
    ($freereg:ident, $out:expr, $pos: expr, $arg_num:expr, $stack_arg_num:expr,
     $target:expr, $out_wrap:expr, []) => {{
        let reg = reg_id!($freereg);
        $crate::platform::write_in_wrapper_const_args($out, $arg_num, $pos, reg, $out_wrap, $target)
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
macro_rules! write_out_wrapper {
    (yes, $out:expr, $reg_id:expr, $orig:expr, $arg_num:expr, [$($aloc:ident),*]) => {
        // Just jump to the original code.
        // TODO: Are there any unusual calling conventions in exported functions?
        // In wrapper doesn't handle them really either, but it has register order
        // softcoded.
        $crate::platform::write_jump($out, $reg_id, $orig)
    };
    (no, $out:expr, $reg_id:expr, $orig:expr, $arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let (out, pos) = write_out_wrapper!(no_args, $out, $orig, $arg_num + 1, [$($aloc),*]);
        let loc = reg_id_or_stack!($loc);
        let (out, pos) = $crate::platform::write_out_argument(out, pos, loc, $arg_num);
        $crate::platform::write_out_call(out, $reg_id, $orig, pos)
    }};
    (no_args, $out:expr, $orig:expr, $arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let (out, pos) = write_out_wrapper!(no_args, $out, $orig, $arg_num + 1, [$($aloc),*]);
        let loc = reg_id_or_stack!($loc);
        $crate::platform::write_out_argument(out, pos, loc, $arg_num)
    }};
    (no_args, $out:expr, $orig:expr, $arg_num:expr, []) => {{
        ($out, 1)
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
    ($is_pub:ident ~ $abi:ident, $ord:expr, $name:ident, $ret:ty, [$([$args:tt])*]) => {
        // Increase arg name count if needed...
        name_args!(nope, [imp, $is_pub, $abi, $ord, $name, $ret], [], [$($args)*],
                   [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10],
                   [rcx, rdx, r8, r9, stack, stack, stack, stack, stack, stack]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! do_addr_hook {
    ($is_pub:ident ~ $abi:ident, $base:expr, $addr:expr, $name:ident, $ret:ty, [$([$args:tt])*]) => {
        name_args!(nope, [addr, $is_pub, $abi, $base, $addr, $name, $ret], [], [$($args)*],
                   [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10],
                   [rcx, rdx, r8, r9, stack, stack, stack, stack, stack, stack]);
    };
}
