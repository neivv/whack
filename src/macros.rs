pub trait ExportHook<Callback> {
    fn wrapper_size() -> usize;
    fn default_export() -> ::Export<'static>;
    unsafe fn write_wrapper(out: *mut u8, target: Callback, orig_addr: *const u8);
}

#[macro_export]
macro_rules! export_hook {
    (pub extern "system" ($ord:expr) $name:ident($($aty:ty),*) -> $ret:ty) => {
        impl_hook!(yes ~ system, $ord, $name, $ret, [$([$aty])*]);
    };
    (extern "system" ($ord:expr) $name:ident($($aty:ty),*) -> $ret:ty) => {
        impl_hook!(no ~ system, $ord, $name, $ret, [$([$aty])*]);
    };
    (pub extern "system" $name:ident($($aty:ty),*)) => {
        impl_hook!(yes ~ system, -1i32, $name, (), [$([$aty])*]);
    };
    (pub extern "system" $name:ident($($aty:ty),*) -> $ret:ty) => {
        impl_hook!(yes ~ system, -1i32, $name, $ret, [$([$aty])*]);
    };
    (extern "system" $name:ident($($aty:ty),*)) => {
        impl_hook!(no ~ system, -1i32, $name, (), [$([$aty])*]);
    };
    (extern "system" $name:ident($($aty:ty),*) -> $ret:ty) => {
        impl_hook!(no ~ system, -1i32, $name, $ret, [$([$aty])*]);
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
macro_rules! name_args {
    ($is_pub:ident ~ $abi:ident, $ord:expr, $name:ident, $ret:ty, [$([$oki:ident @ $okl:ident: $okt:ty])*],
        [$next_ty:ty, $($rest_ty:ty,)*],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident, $($rest_loc:ident),*]) =>
    {
        name_args!($is_pub ~ $abi, $ord, $name, $ret,
                   [$([$oki @ $okl: $okt])* [$next_id @ $next_loc: $next_ty]],
                   [$($rest_ty,)*], [$($rest_id),*], [$($rest_loc),*]);
    };
    ($is_pub:ident ~ $abi:ident, $ord:expr, $name:ident, $ret:ty, [$([$oki:ident @ $okl:ident: $okt:ty])*], [], [$($rest:ident),*], [$($rest_loc:ident),*]) => {
        impl_named!($is_pub ~ $abi, $ord, $name, $ret, $([$oki @ $okl: $okt])*);
    };
}

