#[macro_export]
#[doc(hidden)]
macro_rules! whack_reg_id {
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
macro_rules! whack_impl_addr_hook {
    ($is_pub:ident, stdcall, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        whack_impl_addr_hook!(true, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($is_pub:ident, cdecl, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        whack_impl_addr_hook!(false, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($stdcall:expr, $is_pub:ident, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        whack_maybe_pub_struct!($is_pub, $name);
        whack_hook_impl_private!(no, $stdcall, $name, $ret, $([$an @ $aloc($apos): $aty])*);
        #[allow(clippy::unused_unit)]
        impl<T> $crate::AddressHookClosure<T> for $name
        where T: Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret + Sized + 'static,
        {
            fn address() -> usize {
                ($addr as usize).checked_sub($base).unwrap()
            }

            whack_hook_wrapper_impl!($ret, $([$aty])*);
        }

        #[allow(clippy::unused_unit)]
        impl $crate::AddressHook for $name {
            fn wrapper_assembler(target: *const u8) -> $crate::platform::HookWrapAssembler {
                $name::gen_wrap_private(target)
            }

            whack_addr_hook_common!($ret, [$($aty),*], [$($an),*]);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_impl_import_hook {
    ($is_pub:ident, system, $ord:expr, $name:ident, $ret:ty,
     $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        whack_impl_import_hook!($is_pub, stdcall, $ord, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($is_pub:ident, stdcall, $ord:expr, $name:ident, $ret:ty,
     $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        whack_maybe_pub_struct!($is_pub, $name);
        whack_hook_impl_private!(yes, true, $name, $ret, $([$an @ $aloc($apos): $aty])*);
        #[allow(clippy::unused_unit)]
        impl<T> $crate::ExportHookClosure<T> for $name
        where T: Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret + Sized + 'static,
        {
            fn default_export() -> $crate::Export<'static> {
                if $ord as i32 == -1 {
                    let name = stringify!($name);
                    $crate::Export::Name(name.as_bytes())
                } else {
                    $crate::Export::Ordinal($ord as u16)
                }
            }

            whack_hook_wrapper_impl!($ret, $([$aty])*);
        }

        #[allow(clippy::unused_unit)]
        impl $crate::ExportHook for $name {
            fn wrapper_assembler(target: *const u8) -> $crate::platform::HookWrapAssembler {
                $name::gen_wrap_private(target)
            }

            whack_export_hook_common!($ret, [$($aty),*], [$($an),*]);
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_hook_impl_private {
    ($fnptr_hook:ident, $stdcall:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        #[allow(clippy::unused_unit)]
        impl $name {
            // caller -> assembly wrap -> in_wrap -> hook.
            // If the hook wishes to call original function,
            // then it'll go hook -> out_wrap -> assembly -> original.
            // Orig is pointer to the assembly wrapper which calls original function,
            // Real is pointer to the fat pointer of hook Fn(...).
            extern fn in_wrap(
                $($an: $aty,)*
                orig: extern fn($($aty),*) -> $ret,
                real: *const *const dyn Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret,
            ) -> $ret {
                let real: &dyn Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret =
                    unsafe { &**real };
                real($($an,)* orig)
            }

            #[allow(unused_mut)]
            fn gen_wrap_private(target: *const u8) -> $crate::platform::HookWrapAssembler {
                let in_wrap_addr = $name::in_wrap as *const u8;
                let mut wrapper =
                    $crate::platform::HookWrapAssembler::new(in_wrap_addr, target, $stdcall);
                whack_hook_initialize_wrapper!(wrapper, [$($aloc, $apos),*]);
                wrapper
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_hook_wrapper_impl {
    ($ret:ty, $([$aty:ty])*) => {
        // Allowing this is slightly sketchy, relying on Vec's allocation alignment and
        // that sizeof(T) is aligned as well
        #[allow(clippy::unused_unit)]
        fn write_target_objects(target: T) -> Box<[u8]> {
            unsafe {
                let fat_ptr_size = ::std::mem::size_of::<
                    *const dyn Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret
                >();
                let size = ::std::mem::size_of::<T>() + fat_ptr_size;
                let out = vec![0u8; size].into_boxed_slice();

                let target_mem = out.as_ptr().add(fat_ptr_size) as *mut T;
                ::std::ptr::write_unaligned(target_mem, target);
                let target_ptr = target_mem;
                ::std::ptr::write_unaligned(
                    out.as_ptr() as *mut *const dyn Fn($($aty,)* _) -> $ret,
                    target_ptr,
                );
                out
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_hook_initialize_wrapper {
    ($wrapper:expr, [stack, $next_pos:expr $(,$aloc:ident, $apos:expr)*]) => {{
        $wrapper.add_arg($crate::platform::Location::Stack($next_pos));
        whack_hook_initialize_wrapper!($wrapper, [$($aloc, $apos),*]);
    }};
    ($wrapper:expr, [$next:ident, $next_pos:expr $(,$aloc:ident, $apos:expr)*]) => {{
        let reg_id = whack_reg_id!($next);
        $wrapper.add_arg($crate::platform::Location::Register(reg_id));
        whack_hook_initialize_wrapper!($wrapper, [$($aloc, $apos),*]);
    }};
    ($wrapper:expr, []) => {
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_name_args {
    ([$($rest:tt),*], [$($args:tt)*]) => {
        whack_name_args_recurse!(nope, 0, [$($rest),*], [], [$($args)*],
            [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15],
            [stack(0), stack(1), stack(2), stack(3), stack(4),
            stack(5), stack(6), stack(7), stack(8), stack(9),
            stack(10), stack(11), stack(12), stack(13), stack(14)]);
    };
}
