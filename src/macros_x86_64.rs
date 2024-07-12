#[macro_export]
#[doc(hidden)]
macro_rules! whack_reg_id {
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
macro_rules! whack_impl_addr_hook {
    ($is_pub:ident, cdecl, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        whack_impl_addr_hook!(rax, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($freereg:ident, $is_pub:ident, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        whack_maybe_pub_struct!($is_pub, $name);
        whack_hook_impl_private!(no, $name, $freereg, $ret, $([$an @ $aloc($apos): $aty])*);
        #[allow(clippy::unused_unit)]
        impl<T> $crate::AddressHookClosure<T> for $name
        where T: Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret + Sized + 'static,
        {
            fn address() -> usize {
                ($addr as usize).checked_sub($base).unwrap()
            }

            fn wrapper_assembler(target: *const u8) -> $crate::platform::HookWrapAssembler {
                $name::gen_wrap_private::<T>(target)
            }

            whack_hook_wrapper_impl!($ret, $([$aty])*);
        }

        #[allow(clippy::unused_unit)]
        impl $crate::AddressHook for $name {
            whack_addr_hook_common!($ret, [$($aty),*], [$($an),*]);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_impl_import_hook {
    ($is_pub:ident, system, $ord:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        whack_impl_import_hook!(rax, $is_pub, $ord, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($freereg:ident, $is_pub:ident, $ord:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        whack_maybe_pub_struct!($is_pub, $name);
        whack_hook_impl_private!(yes, $name, $freereg, $ret, $([$an @ $aloc($apos): $aty])*);
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

            fn wrapper_assembler(target: *const u8) -> $crate::platform::HookWrapAssembler {
                $name::gen_wrap_private::<T>(target)
            }

            whack_hook_wrapper_impl!($ret, $([$aty])*);
        }

        #[allow(clippy::unused_unit)]
        impl $crate::ExportHook for $name {
            whack_export_hook_common!($ret, [$($aty),*], [$($an),*]);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_hook_impl_private {
    ($fnptr_hook:ident, $name:ident, $freereg:ident, $ret:ty, $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        #[allow(clippy::unused_unit)]
        impl $name {
            // caller -> assembly wrap -> in_wrap -> hook.
            // If the hook wishes to call original function,
            // then it'll go hook -> out_wrap -> assembly -> original.
            // Orig is pointer to the assembly wrapper which calls original function,
            // Real is pointer to the fat pointer of hook Fn(...).
            extern fn in_wrap<F>(
                $($an: $aty,)*
                orig: extern fn($($aty),*) -> $ret,
                real: *const F,
            ) -> $ret
            where F: Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret + Sized + 'static,
            {
                let real: &F = unsafe { &*real };
                real($($an,)* orig)
            }

            #[allow(unused_mut)]
            fn gen_wrap_private<F>(target: *const u8) -> $crate::platform::HookWrapAssembler
            where F: Fn($($aty,)* unsafe extern fn($($aty),*) -> $ret) -> $ret + Sized + 'static,
            {
                let in_wrap_addr = $name::in_wrap::<F> as *const u8;
                // TODO? Currently stdcall == false
                let mut wrapper =
                    $crate::platform::HookWrapAssembler::new(in_wrap_addr, target, false);
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
        fn write_target_objects(target: T) -> $crate::TypeErasedBox {
            Box::new(target).into()
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
            [rcx(0), rdx(0), r8(0), r9(0),
            stack(4), stack(5), stack(6), stack(7), stack(8), stack(9), stack(10),
            stack(11), stack(12), stack(13), stack(14)]);
    };
}
