pub trait AddressHook<Callback> {
    unsafe fn wrapper_size(orig: *const u8) -> usize;
    fn address(base: usize) -> usize;
    unsafe fn write_wrapper(out: *mut u8, target: Callback, orig_addr: *mut u8);
}

pub trait ExportHook<Callback> {
    unsafe fn wrapper_size(orig: *const u8) -> usize;
    fn default_export() -> ::Export<'static>;
    unsafe fn write_wrapper(out: *mut u8, target: Callback, orig_addr: *mut u8);
}

#[macro_export]
macro_rules! export_hook {
    (pub extern "system" ($ord:expr) $name:ident($($aty:tt)*) -> $ret:ty) => {
        impl_hook!(yes ~ system, $ord, $name, $ret, [$([$aty])*]);
    };
    (extern "system" ($ord:expr) $name:ident($($aty:tt)*) -> $ret:ty) => {
        impl_hook!(no ~ system, $ord, $name, $ret, [$([$aty])*]);
    };
    (pub extern "system" $name:ident($($aty:tt)*)) => {
        impl_hook!(yes ~ system, -1i32, $name, (), [$([$aty])*]);
    };
    (pub extern "system" $name:ident($($aty:tt)*) -> $ret:ty) => {
        impl_hook!(yes ~ system, -1i32, $name, $ret, [$([$aty])*]);
    };
    (extern "system" $name:ident($($aty:tt)*)) => {
        impl_hook!(no ~ system, -1i32, $name, (), [$([$aty])*]);
    };
    (extern "system" $name:ident($($aty:tt)*) -> $ret:ty) => {
        impl_hook!(no ~ system, -1i32, $name, $ret, [$([$aty])*]);
    };
}

#[macro_export]
macro_rules! declare_hooks {
    ($base:expr, $($addr:expr => $name:ident($($args:tt)*) $(-> $ret:ty)*;)*) => {
        $(address_hook!($base, $addr, pub $name($($args)*) $(-> $ret)*);)*
    };
}

#[macro_export]
macro_rules! address_hook {
    ($base:expr, $addr:expr, pub $name:ident($($aty:tt)*)) => {
        do_addr_hook!(yes ~ cdecl, $base, $addr, $name, (), [$([$aty])*]);
    };
    ($base:expr, $addr:expr, pub $name:ident($($aty:tt)*) -> $ret:ty) => {
        do_addr_hook!(yes ~ cdecl, $base, $addr, $name, $ret, [$([$aty])*]);
    };
    ($base:expr, $addr:expr, $name:ident($($aty:tt)*)) => {
        do_addr_hook!(no ~ cdecl, $base, $addr, $name, (), [$([$aty])*]);
    };
    ($base:expr, $addr:expr, $name:ident($($aty:tt)*) -> $ret:ty) => {
        do_addr_hook!(no ~ cdecl, $base, $addr, $name, $ret, [$([$aty])*]);
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


/// Gives names to the argument types, and extracts their locations, if defined.
/// If no locations are defined, they are assigned from [next_loc, rest_loc] list,
/// but if even a single one is, any unspecified become stack locations.
/// (Sensical? As on x86, the default list is just [stack, stack, ...])
#[macro_export]
#[doc(hidden)]
macro_rules! name_args {
    // With @location
    (nope, [$($other:tt),*], [$([$oki:ident @ $okl:ident / $imploc:ident: $okt:ty])*],
        [@ $loc:ident $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident, $($rest_loc:ident),*]) =>
    {
        name_args!(yup, [$($other),*],
                  [$([$oki @ $imploc: $okt])* [$next_id @ $loc: $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    (yup, [$($other:tt),*], [$([$oki:ident @ $okl:ident: $okt:ty])*],
        [@ $loc:ident $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, [$($other),*],
                  [$([$oki @ $okl: $okt])* [$next_id @ $loc: $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    // Last arg @location
    (nope, [$($other:tt),*], [$([$oki:ident @ $okl:ident / $imploc:ident: $okt:ty])*],
        [@ $loc:ident $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident, $($rest_loc:ident),*]) =>
    {
        name_args!(yup, [$($other),*],
                  [$([$oki @ $imploc: $okt])* [$next_id @ $loc: $next_ty]],
                  [], [$($rest_id),*]);
    };
    (yup, [$($other:tt),*], [$([$oki:ident @ $okl:ident: $okt:ty])*],
        [@ $loc:ident $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, [$($other),*],
                  [$([$oki @ $okl: $okt])* [$next_id @ $loc: $next_ty]],
                  [], [$($rest_id),*]);
    };
    // Without @location
    (nope, [$($other:tt),*], [$([$oki:ident @ $okl:ident / $imploc:ident: $okt:ty])*],
        [$next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident, $($rest_loc:ident),*]) =>
    {
        name_args!(nope, [$($other),*],
                  [$([$oki @ $okl / $imploc: $okt])* [$next_id @ $next_loc / stack: $next_ty]],
                  [$($rest_args)*], [$($rest_id),*], [$($rest_loc),*]);
    };
    (yup, [$($other:tt),*], [$([$oki:ident @ $okl:ident: $okt:ty])*],
        [$next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, [$($other),*],
                  [$([$oki @ $okl: $okt])* [$next_id @ stack: $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    // Last arg without @location
    (nope, [$($other:tt),*], [$([$oki:ident @ $okl:ident / $imploc:ident: $okt:ty])*],
        [$next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident, $($rest_loc:ident),*]) =>
    {
        name_args!(nope, [$($other),*],
                  [$([$oki @ $okl / $imploc: $okt])* [$next_id @ $next_loc / stack: $next_ty]],
                  [], [$($rest_id),*], [$($rest_loc),*]);
    };
    (yup, [$($other:tt),*], [$([$oki:ident @ $okl:ident: $okt:ty])*],
        [$next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, [$($other),*],
                  [$([$oki @ $okl: $okt])* [$next_id @ stack: $next_ty]],
                  [], [$($rest_id),*]);
    };
    // Finish
    (nope, [addr, $($other:tt),*], [$([$oki:ident @ $okl:ident / $imploc:ident: $okt:ty])*], [],
     [$($rest:ident),*], [$($rest_loc:ident),*]) => {
        impl_addr_hook!($($other,)* $([$oki @ $okl: $okt])*);
    };
    (yup, [addr, $($other:tt),*], [$([$oki:ident @ $okl:ident: $okt:ty])*], [],
     [$($rest:ident),*]) => {
        impl_addr_hook!($($other,)* $([$oki @ $okl: $okt])*);
    };
    (nope, [imp, $($other:tt),*], [$([$oki:ident @ $okl:ident / $imploc:ident: $okt:ty])*], [],
     [$($rest:ident),*], [$($rest_loc:ident),*]) => {
        impl_import_hook!($($other,)* $([$oki @ $okl: $okt])*);
    };
    (yup, [imp, $($other:tt),*], [$([$oki:ident @ $okl:ident: $okt:ty])*], [],
     [$($rest:ident),*]) => {
        impl_import_hook!($($other,)* $([$oki @ $okl: $okt])*);
    };
}
