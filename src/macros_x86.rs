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
macro_rules! impl_addr_hook {
    ($is_pub:ident, stdcall, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        impl_addr_hook!(true, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($is_pub:ident, cdecl, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        impl_addr_hook!(false, $is_pub, $base, $addr, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($stdcall:expr, $is_pub:ident, $base:expr, $addr:expr, $name:ident, $ret:ty,
        $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) =>
    {
        maybe_pub_struct!($is_pub, $name);
        hook_impl_private!(no, $stdcall, $name, $ret, $([$an @ $aloc($apos): $aty])*);
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static>
            $crate::AddressHookClosure<T> for $name
        {
            fn address(current_base: usize) -> usize {
                current_base.wrapping_sub($base).wrapping_add($addr)
            }

            hook_wrapper_impl!(no, $stdcall, $name, $ret, $([$an @ $aloc($apos): $aty])*);
        }

        impl_address_hook!($name, $ret, [$($aty),*], [$($an),*]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_import_hook {
    ($is_pub:ident, system, $ord:expr, $name:ident, $ret:ty,
     $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        impl_import_hook!($is_pub, stdcall, $ord, $name, $ret, $([$an @ $aloc($apos): $aty])*);
    };
    ($is_pub:ident, stdcall, $ord:expr, $name:ident, $ret:ty,
     $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        maybe_pub_struct!($is_pub, $name);
        hook_impl_private!(yes, true, $name, $ret, $([$an @ $aloc($apos): $aty])*);
        impl<T: Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret + Sized + 'static> $crate::ExportHookClosure<T> for $name {
            fn default_export() -> $crate::Export<'static> {
                if $ord as i32 == -1 {
                    let name = stringify!($name);
                    $crate::Export::Name(name.as_bytes())
                } else {
                    $crate::Export::Ordinal($ord as u16)
                }
            }

            hook_wrapper_impl!(yes, true, $name, $ret, $([$an @ $aloc($apos): $aty])*);
        }

        impl_export_hook!($name, $ret, [$($aty),*], [$($an),*]);
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_impl_private {
    ($fnptr_hook:ident, $stdcall:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
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
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_wrapper_impl {
    ($fnptr_hook:ident, $stdcall:expr, $name:ident, $ret:ty, $([$an:ident @ $aloc:ident($apos:expr): $aty:ty])*) => {
        #[allow(unused_mut)]
        unsafe fn write_wrapper(preserve_regs: bool,
                                target: T,
                                orig_addr: Option<*mut u8>,
                                exec_heap: &mut $crate::platform::ExecutableHeap) -> *const u8 {
            let fnptr_hook = yes_no!($fnptr_hook);
            let in_wrap_addr = $name::in_wrap as *const u8;
            let orig = orig_addr.unwrap_or(::std::ptr::null_mut());
            let mut wrapper = $crate::platform::WrapAssembler::new(orig,
                                                                   fnptr_hook,
                                                                   $stdcall,
                                                                   preserve_regs);
            hook_initialize_wrapper!(wrapper, [$($aloc, $apos),*]);
            let target_size = ::std::mem::size_of::<T>() +
                ::std::mem::size_of::<*const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret>();
            let in_wrapper = wrapper.write(exec_heap, in_wrap_addr, target_size, |out| {
                let fat_ptr_size = ::std::mem::size_of::<*const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret>();
                let target_mem = out.offset(fat_ptr_size as isize) as *mut T;
                ::std::ptr::copy_nonoverlapping(&target, target_mem, 1);
                ::std::mem::forget(target);
                let target_ptr: *const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret = target_mem;
                let ptr_pos = out as *mut *const Fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret;
                ::std::ptr::copy_nonoverlapping(&target_ptr, ptr_pos, 1);
                ::std::mem::forget(target_ptr);
            });
            if let Some(_orig_addr) = orig_addr {
                write_hooking_jump!($fnptr_hook, _orig_addr, in_wrapper);
            }
            in_wrapper
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! hook_initialize_wrapper {
    ($wrapper:expr, [stack, $next_pos:expr $(,$aloc:ident, $apos:expr)*]) => {{
        $wrapper.add_arg($crate::platform::Location::Stack($next_pos));
        hook_initialize_wrapper!($wrapper, [$($aloc, $apos),*]);
    }};
    ($wrapper:expr, [$next:ident, $next_pos:expr $(,$aloc:ident, $apos:expr)*]) => {{
        let reg_id = reg_id!($next);
        $wrapper.add_arg($crate::platform::Location::Register(reg_id));
        hook_initialize_wrapper!($wrapper, [$($aloc, $apos),*]);
    }};
    ($wrapper:expr, []) => {
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
macro_rules! whack_name_args {
    ([$($rest:tt),*], [$([$args:tt])*]) => {
        whack_name_args_recurse!(nope, 0, [$($rest),*], [], [$($args)*],
            [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11],
            [stack(0), stack(1), stack(2), stack(3), stack(4),
            stack(5), stack(6), stack(7), stack(8), stack(9),
            stack(10)]);
    };
}
