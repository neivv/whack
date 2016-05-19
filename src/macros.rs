pub trait AddressHookClosure<Callback> {
    fn address(base: usize) -> usize;
    unsafe fn write_wrapper(preserve_regs: bool,
                            target: Callback,
                            orig_addr: *mut u8,
                            exec_heap: &mut ::platform::ExecutableHeap
                           ) -> *const u8;
}

pub trait AddressHook {
    type Fnptr;
    type OptFnptr;
    unsafe fn hook<'a>(self, patch: &mut ::ModulePatch<'a>, val: Self::Fnptr) -> ::Patch;
    unsafe fn hook_opt<'a>(self, patch: &mut ::ModulePatch<'a>, val: Self::OptFnptr) -> ::Patch;
    unsafe fn call_hook<'a>(self, patch: &mut ::ModulePatch<'a>, val: Self::Fnptr) -> ::Patch;
}

pub trait ExportHookClosure<Callback> {
    fn default_export() -> ::Export<'static>;
    unsafe fn write_wrapper(preserve_regs: bool,
                            target: Callback,
                            orig_addr: *mut u8,
                            exec_heap: &mut ::platform::ExecutableHeap
                           ) -> *const u8;
}

pub trait ExportHook {
    type Fnptr;
    type OptFnptr;
    fn import<'a>(self, patch: &mut ::AnyModulePatch<'a>, dll: &[u8],
                  val: Self::Fnptr) -> Option<::Patch>;
    fn import_opt<'a>(self, patch: &mut ::AnyModulePatch<'a>, dll: &[u8],
                  val: Self::OptFnptr) -> Option<::Patch>;
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
    (stdcall, $base:expr, $($addr:expr => $name:ident($($args:tt)*) $(-> $ret:ty)*;)*) => {
        $(address_hook!(stdcall, $base, $addr, pub $name($($args)*) $(-> $ret)*);)*
    };
    ($base:expr, $($addr:expr => $name:ident($($args:tt)*) $(-> $ret:ty)*;)*) => {
        $(address_hook!(cdecl, $base, $addr, pub $name($($args)*) $(-> $ret)*);)*
    };
}

#[macro_export]
macro_rules! address_hook {
    ($abi:ident, $base:expr, $addr:expr, pub $name:ident($($aty:tt)*)) => {
        do_addr_hook!(yes ~ $abi, $base, $addr, $name, (), [$([$aty])*]);
    };
    ($abi:ident, $base:expr, $addr:expr, pub $name:ident($($aty:tt)*) -> $ret:ty) => {
        do_addr_hook!(yes ~ $abi, $base, $addr, $name, $ret, [$([$aty])*]);
    };
    ($abi:ident, $base:expr, $addr:expr, $name:ident($($aty:tt)*)) => {
        do_addr_hook!(no ~ $abi, $base, $addr, $name, (), [$([$aty])*]);
    };
    ($abi:ident, $base:expr, $addr:expr, $name:ident($($aty:tt)*) -> $ret:ty) => {
        do_addr_hook!(no ~ $abi, $base, $addr, $name, $ret, [$([$aty])*]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_address_hook {
    ($name:ident, $ret:ty, [$($aty:ty),*], [$($an:ident),*]) => {
        impl $crate::AddressHook for $name {
            type Fnptr = unsafe fn($($aty),*) -> $ret;
            type OptFnptr = unsafe fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret;
            unsafe fn hook<'a>(self, patch: &mut $crate::ModulePatch<'a>, val: Self::Fnptr) -> $crate::Patch
            {
                patch.hook_closure(self, move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                    val($($an),*)
                })
            }
            unsafe fn hook_opt<'a>(self, patch: &mut $crate::ModulePatch<'a>, val: Self::OptFnptr) -> $crate::Patch
            {
                patch.hook_closure(self, move |$($an,)* orig: &Fn($($aty),*) -> $ret| {
                    val($($an,)* orig)
                })
            }
            unsafe fn call_hook<'a>(self, patch: &mut $crate::ModulePatch<'a>, val: Self::Fnptr) -> $crate::Patch
            {
                patch.hook_closure_internal(true, self, move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                    val($($an),*)
                })
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_export_hook {
    ($name:ident, $ret:ty, [$($aty:ty),*], [$($an:ident),*]) => {
        impl $crate::ExportHook for $name {
            type Fnptr = unsafe fn($($aty),*) -> $ret;
            type OptFnptr = unsafe fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret;
            fn import<'a>(self, patch: &mut $crate::AnyModulePatch<'a>, dll: &[u8],
                          val: Self::Fnptr) -> Option<$crate::Patch>
            {
                patch.import_hook_closure(dll, self, move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                    unsafe { val($($an),*) }
                })
            }
            fn import_opt<'a>(self, patch: &mut $crate::AnyModulePatch<'a>, dll: &[u8],
                          val: Self::OptFnptr) -> Option<$crate::Patch>
            {
                patch.import_hook_closure(dll, self, move |$($an,)* orig: &Fn($($aty),*) -> $ret| {
                    unsafe { val($($an,)* orig) }
                })
            }
        }
    }
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
macro_rules! yes_no {
    (yes) => { true };
    (no) => { false };
}

/// Gives names to the argument types, and extracts their locations, if defined.
/// If no locations are defined, they are assigned from [next_loc, rest_loc] list,
/// but if even a single one is, any unspecified become stack locations.
/// (Sensical? As on x86, the default list is just [stack, stack, ...])
#[macro_export]
#[doc(hidden)]
macro_rules! name_args {
    // @ stack
    (nope, $imp_stack_pos:expr, [$($other:tt),*],
        [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $imploc($impp): $okt])* [$next_id @ stack($pos): $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $okl($okp): $okt])* [$next_id @ stack($pos): $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    // Last arg @ stack
    (nope, $imp_stack_pos:expr, [$($other:tt),*],
        [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $imploc($impp): $okt])* [$next_id @ stack($pos): $next_ty]],
                  [], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $okl($okp): $okt])* [$next_id @ stack($pos): $next_ty]],
                  [], [$($rest_id),*]);
    };
    // With @location
    (nope, $imp_stack_pos:expr, [$($other:tt),*],
        [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [@ $loc:ident $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $imploc($impp): $okt])* [$next_id @ $loc(0): $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ $loc:ident $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $okl($okp): $okt])* [$next_id @ $loc(0): $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    // Last arg @location
    (nope, $imp_stack_pos:expr, [$($other:tt),*],
        [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [@ $loc:ident $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $imploc($impp): $okt])* [$next_id @ $loc(0): $next_ty]],
                  [], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ $loc:ident $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, $imp_stack_pos, [$($other),*],
                  [$([$oki @ $okl($okp): $okt])* [$next_id @ $loc(0): $next_ty]],
                  [], [$($rest_id),*]);
    };
    // Without @location
    (nope, $imp_stack_pos:expr, [$($other:tt),*],
     [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [$next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        name_args!(nope, $imp_stack_pos + 1, [$($other),*],
                  [$([$oki @ $okl($okp) / $imploc($impp): $okt])*
                      [$next_id @ $next_loc($nextp) / stack($imp_stack_pos): $next_ty]],
                  [$($rest_args)*], [$($rest_id),*], [$($rest_loc($rest_pos)),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [$next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, $imp_stack_pos + 1, [$($other),*],
                  [$([$oki @ $okl($okp): $okt])* [$next_id @ stack($imp_stack_pos): $next_ty]],
                  [$($rest_args)*], [$($rest_id),*]);
    };
    // Last arg without @location
    (nope, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [$next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        name_args!(nope, $imp_stack_pos + 1,
                   [$($other),*],
                   [$([$oki @ $okl($okp) / $imploc($impp): $okt])*
                       [$next_id @ $next_loc($nextp) / stack($imp_stack_pos): $next_ty]],
                   [], [$($rest_id),*], [$($rest_loc($rest_pos)),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [$next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        name_args!(yup, $imp_stack_pos + 1, [$($other),*],
                  [$([$oki @ $okl($okp): $okt])* [$next_id @ stack($imp_stack_pos): $next_ty]],
                  [], [$($rest_id),*]);
    };
    // Finish
    (nope, $imp_stack_pos:expr, [addr, $($other:tt),*],
     [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*], [],
     [$($rest:ident),*], [$($rest_loc:ident($rest_pos:expr)),*]) => {
        impl_addr_hook!($($other,)* $([$oki @ $okl($okp): $okt])*);
    };
    (yup, $imp_stack_pos:expr, [addr, $($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*], [],
     [$($rest:ident),*]) => {
        impl_addr_hook!($($other,)* $([$oki @ $okl($okp): $okt])*);
    };
    (nope, $imp_stack_pos:expr, [imp, $($other:tt),*],
     [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*], [],
     [$($rest:ident),*], [$($rest_loc:ident($rest_pos:expr)),*]) => {
        impl_import_hook!($($other,)* $([$oki @ $okl($okp): $okt])*);
    };
    (yup, $imp_stack_pos:expr, [imp, $($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*], [],
     [$($rest:ident),*]) => {
        impl_import_hook!($($other,)* $([$oki @ $okl($okp): $okt])*);
    };
}
