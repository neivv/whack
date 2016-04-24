#[macro_export]
#[doc(hidden)]
macro_rules! reg_id {
    (eax) => { 0 };
    (ecx) => { 1 };
    (edx) => { 2 };
    (ebx) => { 3 };
    (esp) => { 4 };
    (ebp) => { 5 };
    (esi) => { 6 };
    (edi) => { 7 };
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_call {
    ($out:expr, $addr:expr) => {{
        let out = $out;
        *out = 0xe8;
        *(out.offset(1) as *mut usize) = $addr.wrapping_sub(out as usize).wrapping_sub(5);
        out.offset(5)
    }}
}

#[macro_export]
#[doc(hidden)]
macro_rules! push_const_size { () => { 5 } }

#[macro_export]
#[doc(hidden)]
macro_rules! call_const_size { () => { 5 } }

#[macro_export]
#[doc(hidden)]
macro_rules! impl_addr_hook {
    ($is_pub:ident, stdcall, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident: $aty:ty])*) =>
    {
        impl_addr_hook!(true, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc: $aty])*);
    };
    ($is_pub:ident, cdecl, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident: $aty:ty])*) =>
    {
        impl_addr_hook!(false, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc: $aty])*);
    };
    ($stdcall:expr, $is_pub:ident, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident: $aty:ty])*) =>
    {
        maybe_pub_struct!($is_pub, $name);
        hook_impl_private!(no, $stdcall, $name, $ret, $([$an @ $aloc: $aty])*);
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static> $crate::AddressHookClosure<T> for $name {
            fn address(current_base: usize) -> usize {
                current_base.wrapping_sub($base).wrapping_add($addr)
            }

            hook_wrapper_impl!(no, $stdcall, $name, $ret, $([$an @ $aloc: $aty])*);
        }

        impl_address_hook!($name, $ret, [$($aty),*], [$($an),*]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_import_hook {
    ($is_pub:ident, system, $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        impl_import_hook!($is_pub, stdcall, $ord, $name, $ret, $([$an @ $aloc: $aty])*);
    };
    ($is_pub:ident, stdcall, $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
        maybe_pub_struct!($is_pub, $name);
        hook_impl_private!(yes, true, $name, $ret, $([$an @ $aloc: $aty])*);
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static> $crate::ExportHookClosure<T> for $name {
            fn default_export() -> $crate::Export<'static> {
                if $ord as i32 == -1 {
                    let name = stringify!($name);
                    $crate::Export::Name(name.as_bytes())
                } else {
                    $crate::Export::Ordinal($ord as u16)
                }
            }

            hook_wrapper_impl!(yes, true, $name, $ret, $([$an @ $aloc: $aty])*);
        }

        impl_export_hook!($name, $ret, [$($aty),*], [$($an),*]);
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_impl_private {
    ($fnptr_hook:ident, $stdcall:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
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
                    2 * push_const_size!() + in_wrapper_args_size!(3, 0 $(,$aty)*).0 +
                    // Call + pop + ret
                    call_const_size!() + in_wrapper_pop_size!(2 $(,$aty)*) + in_wrapper_ret_size!($stdcall, 0 $(,$aloc)*)
                };
                // Round to 16
                ((needed - 1) | 0xf) + 1
            }

            unsafe fn out_asm_size(_orig: *const u8) -> usize {
                let needed = out_wrapper_args_size!($fnptr_hook, $stdcall, _orig, 0, 0 $(,$aloc)*).0;
                // Round to 16
                ((needed - 1) | 0xf) + 1
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_wrapper_impl {
    ($fnptr_hook:ident, $stdcall:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident: $aty:ty])*) => {
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
            // Push pointer to the target fat pointer (which is placed at end of this wrapper).
            *out_pos = 0x68;
            *(out_pos.offset(1) as *mut usize) = target_addr;
            out_pos = out_pos.offset(5);
            // Push pointer to the wrapper to original function.
            *out_pos = 0x68;
            *(out_pos.offset(1) as *mut usize) = out_wrapper;
            out_pos = out_pos.offset(5);
            // Push args.
            out_pos = write_in_wrapper_args!(out_pos, 3, 0, [$($aloc),*]).0;
            // Call in_wrap()
            out_pos = write_call!(out_pos, in_wrap_addr);
            // Pop in_wrapper arguments. Adds 2 for the two pointers.
            out_pos = pop_wrapper_args!(out_pos, 2 $(,$aty)*);
            // Return.
            out_pos = in_wrapper_return!(out_pos, $stdcall, 0 $(,$aloc)*);
            assert!(out_pos as usize <= out_wrapper);
            out_pos = out_wrapper as *mut u8;
            // OUT WRAPPER
            out_pos = write_out_wrapper!($fnptr_hook, $stdcall, out_pos, orig_addr, 0, [$($aloc),*]);

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

            write_hooking_jump!($fnptr_hook, orig_addr, out);
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_hooking_jump {
    (yes, $src:expr, $dest:expr) => {};
    (no, $src:expr, $dest:expr) => {
        $crate::platform::write_jump($src, $dest)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_in_wrapper_args {
    ($out:expr, $pos:expr, $stack_arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let _next_stack_arg = if_stack!($loc, $stack_arg_num + 1, $stack_arg_num);
        let (out, pos) = write_in_wrapper_args!($out, $pos, _next_stack_arg, [$($aloc),*]);
        let id = reg_id_or_stack!($loc);
        $crate::platform::write_in_wrapper_arg(out, id, pos, $stack_arg_num)
    }};
    ($out:expr, $pos:expr, $stack_arg_num:expr, []) => {
        ($out, 3)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! reg_id_or_stack {
    (stack) => { !0 };
    ($reg:ident) => { reg_id!($reg) };
}

#[macro_export]
#[doc(hidden)]
macro_rules! if_stack {
    (stack, $yes:expr, $no:expr) => { $yes };
    ($other:ident, $yes:expr, $no:expr) => { $no };
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_args_size {
    ($pos:expr, $arg_num:expr, $next:ty $(,$aty:ty)*) => {{
        let (amt, pos) = in_wrapper_args_size!($pos, $arg_num + 1 $(,$aty)*);
        let push_offset = pos + $arg_num;
        (if push_offset * 4 >= 0x20 { amt + 7 } else { amt + 4 }, pos + 1)
    }};
    ($pos: expr, $arg_num:expr) => {
        (0, 3)
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
        if $pos >= 0x20 {
            *out.offset(0) = 0x81;
            *out.offset(1) = 0xc4;
            *(out.offset(2) as *mut u32) = $pos * 4;
            out.offset(6)
        } else {
            *out.offset(0) = 0x83;
            *out.offset(1) = 0xc4;
            *out.offset(2) = $pos as u8 * 4;
            out.offset(3)
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
        if $pos >= 0x20 { 6 } else { 3 }
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_return {
    ($out:expr, $stdcall:expr, $pos:expr, $next:ident $(,$aloc:ident)*) => {{
        let _pos = if_stack!($next, $pos + 1, $pos);
        in_wrapper_return!($out, $stdcall, _pos $(,$aloc)*)
    }};
    ($out:expr, $stdcall:expr, $pos: expr) => {{
        let out = $out;
        if $pos == 0 || !$stdcall {
            *out.offset(0) = 0xc3;
            out.offset(1)
        } else {
            *out.offset(0) = 0xc2;
            *(out.offset(1) as *mut u16) = $pos * 4;
            out.offset(3)
        }
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_ret_size {
    ($stdcall:expr, $pos:expr, $next:ident $(,$aloc:ident)*) => {{
        let _pos = if_stack!($next, $pos + 1, $pos);
        in_wrapper_ret_size!($stdcall, $pos + 1 $(,$aloc)*)
    }};
    ($stdcall:expr, $pos:expr) => {
        if $pos == 0 || !$stdcall { 1 } else { 3 }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_out_wrapper {
    (yes, $stdcall:expr, $out:expr, $orig:expr, $arg_num:expr, [$($aloc:ident),*]) => {{
        let (out, pos) = write_out_wrapper!(inner, $out, $orig, $arg_num + 1, [$($aloc),*]);
        $crate::platform::write_out_call(out, $orig, pos, $stdcall, false)
    }};
    (no, $stdcall:expr, $out:expr, $orig:expr, $arg_num:expr, [$($aloc:ident),*]) => {{
        let (out, pos) = write_out_wrapper!(inner, $out, $orig, $arg_num + 1, [$($aloc),*]);
        $crate::platform::write_out_call(out, $orig, pos, $stdcall, true)
    }};
    (inner, $out:expr, $orig:expr, $arg_num:expr, [$loc:ident $(,$aloc:ident)*]) => {{
        let (out, pos) = write_out_wrapper!(inner, $out, $orig, $arg_num + 1, [$($aloc),*]);
        let loc = reg_id_or_stack!($loc);
        $crate::platform::write_out_argument(out, pos, loc, $arg_num)
    }};
    (inner, $out:expr, $orig:expr, $arg_num:expr, []) => {{
        ($out, 0)
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! out_wrapper_args_size {
    (yes, $stdcall:expr, $orig:expr, $pos:expr, $arg_num:expr, $loc:ident $(,$aloc:ident)*) => {{
        let (amt, pos) = out_wrapper_args_size!(yes, $stdcall, $orig, $pos, $arg_num + 1 $(,$aloc)*);
        let push_offset = pos + $arg_num;
        // Same size applies for both mov reg, [esp + pos], push [esp + pos]
        (if push_offset >= 0x20 { amt + 7 } else { amt + 4 }, if_stack!($loc, pos + 1, pos))
    }};
    (yes, $stdcall:expr, $orig:expr, $pos:expr, $arg_num:expr) => {{
        let arg_add_size = if $stdcall { if $pos + $arg_num >= 0x20 { 6 } else { 3 } } else { 0 };
        (5 + arg_add_size + 1, 0) // Call + esp fixup + ret
    }};
    (no, $stdcall:expr, $orig:expr, $pos:expr, $arg_num:expr, $loc:ident $(,$aloc:ident)*) => {{
        let (amt, pos) = out_wrapper_args_size!(no, $stdcall, $orig, $pos, $arg_num + 1 $(,$aloc)*);
        let push_offset = pos + $arg_num;
        // Same size applies for both mov reg, [esp + pos], push [esp + pos]
        let ins_size = {
            let arg_move_size = if push_offset >= 0x20 { amt + 7 } else { amt + 4 };
            let ret_push_size = if $arg_num == 0 {
                if pos >= 0x20 { amt + 7 } else { amt + 4 }
            } else { 0 };
            arg_move_size + ret_push_size
        };
        (ins_size, if_stack!($loc, pos + 1, pos))
    }};
    (no, $stdcall:expr, $orig:expr, $pos:expr, $arg_num:expr) => {{
        // Push ret + Orig copy + jmp + esp fixup + ret
        let arg_add_size = if $stdcall { if $pos + $arg_num >= 0x20 { 6 } else { 3 } } else { 0 };
        (5 + $crate::platform::copy_instruction_length($orig, 5) + 5 + arg_add_size + 1, 0)
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_hook {
    ($is_pub:ident ~ $abi:ident, $ord:expr, $name:ident, $ret:ty, [$([$args:tt])*]) => {
        // Increase arg name count if needed...
        name_args!(nope, [imp, $is_pub, $abi, $ord, $name, $ret], [], [$($args)*],
                   [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10],
                   [stack, stack, stack, stack, stack, stack, stack, stack, stack, stack]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! do_addr_hook {
    ($is_pub:ident ~ $abi:ident, $base:expr, $addr:expr, $name:ident, $ret:ty, [$([$args:tt])*]) => {
        name_args!(nope, [addr, $is_pub, $abi, $base, $addr, $name, $ret], [], [$($args)*],
                   [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10],
                   [stack, stack, stack, stack, stack, stack, stack, stack, stack, stack]);
    };
}
