pub trait ExportHook<Callback> {
    fn wrapper_size() -> usize;
    fn default_export() -> ::Export<'static>;
    unsafe fn write_wrapper(out: *mut u8, target: Callback, orig_addr: *const u8);
}

#[macro_export]
macro_rules! export_hook {
    (pub extern "stdcall" ($ord:expr) $name:ident($($aty:ty),*) -> $ret:ty) => {
        impl_hook!(yes ~ true, $ord, $name, $ret, [$([$aty])*]);
    };
    (extern "stdcall" ($ord:expr) $name:ident($($aty:ty),*) -> $ret:ty) => {
        impl_hook!(no ~ true, $ord, $name, $ret, [$([$aty])*]);
    };
    (pub extern "stdcall" $name:ident($($aty:ty),*)) => {
        export_hook!(pub extern "stdcall" $name($($aty),*) -> ());
    };
    (pub extern "stdcall" $name:ident($($aty:ty),*) -> $ret:ty) => {
        export_hook!(pub extern "stdcall" (-1i32) $name($($aty),*) -> $ret);
    };
    (extern "stdcall" $name:ident($($aty:ty),*)) => {
        export_hook!(extern "stdcall" $name($($aty),*) -> ());
    };
    (extern "stdcall" $name:ident($($aty:ty),*) -> $ret:ty) => {
        export_hook!(extern "stdcall" (-1i32) $name($($aty),*) -> $ret);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! maybe_pub_struct {
    (yes, $name:ident) => { pub struct $name; };
    (no, $name:ident) => { struct $name; };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_named {
    ($is_pub:ident ~ $stdcall:expr, $ord:expr, $name:ident, $ret:ty, $([$an:ident: $aty:ty])*) => {
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
                    5 + 5 + in_wrapper_args_size!(3, 0 $(,$aty)*).0 +
                    // Call + pop + ret
                    5 + in_wrapper_pop_size!(2 $(,$aty)*) + in_wrapper_ret_size!(0 $(,$aty)*)
                };
                // Round to 16
                ((needed - 1) | 0xf) + 1
            }

            fn out_asm_size() -> usize {
                // Arg pushes + call + ret
                let needed = out_wrapper_args_size!(0, 0 $(,$aty)*).0 + 5 + 1;
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
                // Push pointer to the target fat pointer (which is placed at end of this wrapper).
                *out_pos = 0x68;
                *(out_pos.offset(1) as *mut usize) = target_addr;
                out_pos = out_pos.offset(5);
                // Push pointer to the wrapper to original function.
                *out_pos = 0x68;
                *(out_pos.offset(1) as *mut usize) = out_wrapper;
                out_pos = out_pos.offset(5);
                // Push args.
                out_pos = write_in_wrapper_args!(out_pos, 3, 0 $(,$aty)*).0;
                // Call in_wrap()
                $crate::write_call(out_pos, in_wrap_addr);
                out_pos = out_pos.offset(5);
                // Pop in_wrapper arguments. Adds 2 for the two pointers.
                out_pos = pop_wrapper_args!(out_pos, 2 $(,$aty)*);
                // Return.
                out_pos = in_wrapper_return!(out_pos, 0 $(,$aty)*);
                assert!(out_pos as usize <= out_wrapper);
                out_pos = out_wrapper as *mut u8;
                // OUT WRAPPER
                // Reorder args in the way that the original code expects them.
                out_pos = write_out_wrapper_args!(out_pos, 0, 0 $(,$aty)*).0;
                // Call orig function
                $crate::write_call(out_pos, orig_addr as usize);
                out_pos = out_pos.offset(5);
                // Return
                *out_pos = 0xc3;
                out_pos = out_pos.offset(1);

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
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_in_wrapper_args {
    ($out:expr, $pos:expr, $arg_num:expr, $next:ty $(,$aty:ty)*) => {{
        let (out, pos) = write_in_wrapper_args!($out, $pos, $arg_num + 1 $(,$aty)*);
        let push_offset = pos + $arg_num;
        if push_offset >= 0x20 {
            *out.offset(0) = 0xff;
            *out.offset(1) = 0xb4;
            *out.offset(2) = 0xe4;
            *(out.offset(3) as *mut u32) = push_offset * 4;
            (out.offset(7), pos + 1)
        } else {
            *out.offset(0) = 0xff;
            *out.offset(1) = 0x74;
            *out.offset(2) = 0xe4;
            *out.offset(3) = push_offset as u8 * 4;
            (out.offset(4), pos + 1)
        }
    }};
    ($out:expr, $pos: expr, $arg_num:expr) => {
        ($out, $pos)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! in_wrapper_args_size {
    ($pos:expr, $arg_num:expr, $next:ty $(,$aty:ty)*) => {{
        let (amt, pos) = in_wrapper_args_size!($pos, $arg_num + 1 $(,$aty)*);
        let push_offset = pos + $arg_num;
        (if push_offset >= 0x20 { amt + 7 } else { amt + 4 }, pos + 1)
    }};
    ($pos: expr, $arg_num:expr) => {
        (0, $pos)
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
    ($out:expr, $pos:expr, $next:ty $(,$aty:ty)*) => {
        in_wrapper_return!($out, $pos + 1 $(,$aty)*)
    };
    ($out:expr, $pos: expr) => {{
        let out = $out;
        if $pos == 0 {
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
    ($pos:expr, $next:ty $(,$aty:ty)*) => {
        in_wrapper_ret_size!($pos + 1 $(,$aty)*)
    };
    ($pos:expr) => {
        if $pos == 0 { 1 } else { 3 }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! write_out_wrapper_args {
    ($out:expr, $pos:expr, $arg_num:expr, $next:ty $(,$aty:ty)*) => {{
        let (out, pos) = write_out_wrapper_args!($out, $pos, $arg_num + 1 $(,$aty)*);
        let push_offset = pos + $arg_num + 1;
        if push_offset >= 0x20 {
            *out.offset(0) = 0xff;
            *out.offset(1) = 0xb4;
            *out.offset(2) = 0xe4;
            *(out.offset(3) as *mut u32) = push_offset * 4;
            (out.offset(7), pos + 1)
        } else {
            *out.offset(0) = 0xff;
            *out.offset(1) = 0x74;
            *out.offset(2) = 0xe4;
            *out.offset(3) = push_offset as u8 * 4;
            (out.offset(4), pos + 1)
        }
    }};
    ($out:expr, $pos: expr, $arg_num:expr) => {
        ($out, $pos)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! out_wrapper_args_size {
    ($pos:expr, $arg_num:expr, $next:ty $(,$aty:ty)*) => {{
        let (amt, pos) = out_wrapper_args_size!($pos, $arg_num + 1 $(,$aty)*);
        let push_offset = pos + $arg_num;
        (if push_offset >= 0x20 { amt + 7 } else { amt + 4 }, pos + 1)
    }};
    ($pos: expr, $arg_num:expr) => {
        (0, $pos)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! name_args {
    ($is_pub:ident ~ $stdcall:expr, $ord:expr, $name:ident, $ret:ty, [$([$oki:ident: $okt:ty])*],
        [$next_ty:ty, $($rest_ty:ty,)*],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!($is_pub ~ $stdcall, $ord, $name, $ret,
                   [$([$oki: $okt])* [$next_id: $next_ty]], [$($rest_ty,)*], [$($rest_id),*]);
    };
    ($is_pub:ident ~ $stdcall:expr, $ord:expr, $name:ident, $ret:ty, [$([$oki:ident: $okt:ty])*], [], [$($rest:ident),*]) => {
        impl_named!($is_pub ~ $stdcall, $ord, $name, $ret, $([$oki: $okt])*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_hook {
    ($is_pub:ident ~ $stdcall:expr, $ord:expr, $name:ident, $ret:ty, [$([$argty:ty])*]) => {
        // Increase arg name count if needed...
        name_args!($is_pub ~ $stdcall, $ord, $name, $ret, [], [$($argty,)*], [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10]);
    };
}

