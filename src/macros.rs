use std::borrow::Cow;

use Patch;

pub trait AddressHookClosure<Callback>: AddressHook {
    fn address() -> usize;
    /// Writes pointer to the closure object and the closure itself to memory, they obviously
    /// cannot be relocated afterwards. The boxed slice's beginning ptr is points to the
    /// closure pointer itself (It can be passed to HookWrapCode::write_wrapper).
    fn write_target_objects(target: Callback) -> Box<[u8]>;
}

pub trait AddressHook {
    type Fnptr;
    type OptFnptr;
    unsafe fn hook(self, patch: &mut ::ModulePatcher, val: Self::Fnptr) -> Patch;
    unsafe fn hook_opt(self, patch: &mut ::ModulePatcher, val: Self::OptFnptr) -> Patch;
    unsafe fn call_hook(self, patch: &mut ::ModulePatcher, val: Self::Fnptr) -> Patch;
    unsafe fn custom_calling_convention<'a>(self,
                                            val: Self::Fnptr,
                                            exec_heap: &mut ::platform::ExecutableHeap,
                                            ) -> *const u8;
    /// Generates the wrapper code, which may be used multiple times.
    ///
    /// `target` must be kept alive as long as any of the wrappers generated exist.
    fn wrapper_assembler(target: *const u8) -> ::platform::HookWrapAssembler;
}

pub trait ExportHookClosure<Callback>: ExportHook {
    fn default_export() -> ::Export<'static>;
    fn write_target_objects(target: Callback) -> Box<[u8]>;
}

pub trait ExportHook {
    type Fnptr;
    type OptFnptr;
    fn import(self,
              patch: &mut ::AllModulesPatcher,
              dll: Cow<'static, [u8]>,
              val: Self::Fnptr
              ) -> Patch;
    fn import_opt(self,
                  patch: &mut ::AllModulesPatcher,
                  dll: Cow<'static, [u8]>,
                  val: Self::OptFnptr
                  ) -> Patch;
    fn wrapper_assembler(target: *const u8) -> ::platform::HookWrapAssembler;
}

#[macro_export]
macro_rules! export_hook {
    (pub extern "system" ($ord:expr) $name:ident($($aty:tt)*) -> $ret:ty) => {
        whack_name_args!([imp, yes, system, $ord, $name, $ret], [$([$aty])*]);
    };
    (extern "system" ($ord:expr) $name:ident($($aty:tt)*) -> $ret:ty) => {
        whack_name_args!([imp, no, system, $ord, $name, $ret], [$([$aty])*]);
    };
    (pub extern "system" $name:ident($($aty:tt)*)) => {
        whack_name_args!([imp, yes, system, (-1i32), $name, ()], [$([$aty])*]);
    };
    (pub extern "system" $name:ident($($aty:tt)*) -> $ret:ty) => {
        whack_name_args!([imp, yes, system, (-1i32), $name, $ret], [$([$aty])*]);
    };
    (extern "system" $name:ident($($aty:tt)*)) => {
        whack_name_args!([imp, no, system, (-1i32), $name, ()], [$([$aty])*]);
    };
    (extern "system" $name:ident($($aty:tt)*) -> $ret:ty) => {
        whack_name_args!([imp, no, system, (-1i32), $name, $ret], [$([$aty])*]);
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
        whack_name_args!([addr, yes, $abi, $base, $addr, $name, ()], [$([$aty])*]);
    };
    ($abi:ident, $base:expr, $addr:expr, pub $name:ident($($aty:tt)*) -> $ret:ty) => {
        whack_name_args!([addr, yes, $abi, $base, $addr, $name, $ret], [$([$aty])*]);
    };
    ($abi:ident, $base:expr, $addr:expr, $name:ident($($aty:tt)*)) => {
        whack_name_args!([addr, no, $abi, $base, $addr, $name, ()], [$([$aty])*]);
    };
    ($abi:ident, $base:expr, $addr:expr, $name:ident($($aty:tt)*) -> $ret:ty) => {
        whack_name_args!([addr, no, $abi, $base, $addr, $name, $ret], [$([$aty])*]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_addr_hook_common {
    ($ret:ty, [$($aty:ty),*], [$($an:ident),*]) => {
        type Fnptr = unsafe fn($($aty),*) -> $ret;
        type OptFnptr = unsafe fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret;
        unsafe fn hook(self, patch: &mut $crate::ModulePatcher, val: Self::Fnptr) -> $crate::Patch
        {
            patch.hook_closure(self, move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                val($($an),*)
            })
        }

        unsafe fn hook_opt(self, patch: &mut $crate::ModulePatcher, val: Self::OptFnptr) -> $crate::Patch
        {
            patch.hook_closure(self, move |$($an,)* orig: &Fn($($aty),*) -> $ret| {
                val($($an,)* orig)
            })
        }

        unsafe fn call_hook(self, patch: &mut $crate::ModulePatcher, val: Self::Fnptr) -> $crate::Patch
        {
            patch.call_hook_closure(self, move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                val($($an),*)
            })
        }

        unsafe fn custom_calling_convention<'a>(self,
                                                val: Self::Fnptr,
                                                exec_heap: &mut $crate::platform::ExecutableHeap
                                                ) -> *const u8
        {
            // So that H becomes a valid type
            fn x<H, T>(target: T, exec_heap: &mut $crate::platform::ExecutableHeap) -> *const u8
            where H: $crate::AddressHookClosure<T>
            {
                let target_closure = {
                    let data = H::write_target_objects(target);
                    // "Memory leak", should return (*const u8, Patch)
                    unsafe { (*Box::into_raw(data)).as_ptr() }
                };
                let (wrapper, _) = H::wrapper_assembler(target_closure)
                    .generate_wrapper_code($crate::OrigFuncCallback::None)
                    .write_wrapper(None, exec_heap, None);
                wrapper as *const u8
            }

            let target = move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                val($($an),*)
            };

            x::<Self, _>(target, exec_heap)
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_export_hook_common {
    ($ret:ty, [$($aty:ty),*], [$($an:ident),*]) => {
        type Fnptr = unsafe fn($($aty),*) -> $ret;
        type OptFnptr = unsafe fn($($aty,)* &Fn($($aty),*) -> $ret) -> $ret;
        fn import(self,
                  patch: &mut $crate::AllModulesPatcher,
                  lib: ::std::borrow::Cow<'static, [u8]>,
                  val: Self::Fnptr
                 ) -> $crate::Patch
        {
            patch.import_hook_closure(lib, self, move |$($an,)* _: &Fn($($aty),*) -> $ret| {
                unsafe { val($($an),*) }
            })
        }
        fn import_opt(self,
                      patch: &mut $crate::AllModulesPatcher,
                      lib: ::std::borrow::Cow<'static, [u8]>,
                      val: Self::OptFnptr
                     ) -> $crate::Patch
        {
            patch.import_hook_closure(lib, self, move |$($an,)* orig: &Fn($($aty),*) -> $ret| {
                unsafe { val($($an,)* orig) }
            })
        }
    }
}

/// Declares a list of global variables of a module, which can be accessed with unsafe code.
///
/// The macro arguments are `init_fn`, `base_address`, and a list of variable declarations
/// in form `address => name: type;`
///
/// `init_fn` is a identifier of a function taking a
/// [`&mut ModulePatcher`](struct.ModulePatcher.html), which must be called to initialize the
/// addresses before they are used. This is necessary for handling situations when the module's
/// base address differs from the one specified in `base_address`.
///
/// # Examples
/// ```rust,no_run
/// # #[macro_use] extern crate whack;
/// # fn main() {}
///
/// whack_vars!(init_vars, 0x00400000,
///     0x00400123 => value: u8;
///     0x00400185 => pointer: *mut u32;
///     0x0040023D => array: [u8; 32];
/// );
/// fn access_variables() {
///     let mut patcher = whack::Patcher::new();
///     {
///         let mut active_patcher = patcher.lock().unwrap();
///         let mut patcher = active_patcher.patch_exe(0);
///         unsafe {
///             init_vars(&mut patcher);
///         }
///     }
///
///     // Variables are accessed by dereferencing them.
///     // As they are mutable global state, that is an unsafe operation.
///     unsafe {
///         *value += array[5];
///         let x: u32 = **pointer;
///         array[10] = x as u8;
///     }
/// }
/// ```
#[macro_export]
macro_rules! whack_vars {
    ($init_fn:ident, $base:expr, $($addr:expr => $name:ident: $ty:ty;)*) => {
        $(pub static mut $name: $crate::Variable<$ty> = $crate::Variable {
            address: 0,
            phantom: ::std::marker::PhantomData,
        };)*
        #[cold]
        pub unsafe fn $init_fn(patch: &mut $crate::ModulePatcher) {
            unsafe fn init(base: usize, _heap: &mut $crate::platform::ExecutableHeap) {
                let diff = base - $base;
                $($name.address = $addr + diff;)*
            }
            patch.add_init_fn(init);
        }
    };
}


/// Declares module's internal functions, allowing calling conventions which use registers.
///
/// The macro arguments are `init_fn`, `base_address`, and a list of function declarations
/// in one of following forms:
///
/// * `address => name(args) -> ret;`
/// * `address => name(args);`
///
/// The arguments can use syntax `@reg type` to specify that an argument is in a register,
/// otherwise it is placed to stack. However, if no `@reg` specifiers exist in the argument list,
/// the declaration is interpreted to mean same calling convention as in `extern "C"` (Which
/// means that on x86_64, `x(u8, u8, u8, u8, u8)` is same as
/// `x(@rcx u8, @rdx u8, @r8 u8, @r9 u8, u8)`.
///
/// The default calling convention requires callers to clear stack. If callee-clean
/// is needed, it is specified with `whack_funcs!(stdcall, init_fn, base, ...);`.
///
/// `init_fn` is a identifier of a function taking a
/// [`&mut ModulePatcher`](struct.ModulePatcher.html), which must be called to initialize the
/// functions before they are used. This is necessary for handling situations when the module's
/// base address differs from the one specified in `base_address`.
///
/// # Examples
/// ```rust,no_run
/// # #[macro_use] extern crate whack;
/// # fn main() {}
///
/// #[cfg(target_arch = "x86")]
/// mod fun {
///     whack_funcs!(stdcall, init_funcs, 0x00400000,
///         0x00400000 => first(@eax u32, @edx u32) -> u32;
///         0x00400400 => second(u32, u32, @edi u32, *mut u32);
///     );
/// }
///
/// #[cfg(target_arch = "x86_64")]
/// mod fun {
///     whack_funcs!(init_funcs, 0x00400000,
///         0x00400000 => first(@rax u32, @rdx u32) -> u32;
///         0x00400400 => second(u32, u32, @r14 u32, *mut u32);
///     );
/// }
///
/// fn use_funcs() {
///     let mut patcher = whack::Patcher::new();
///     {
///         let mut active_patcher = patcher.lock().unwrap();
///         let mut patcher = active_patcher.patch_exe(0);
///         unsafe {
///             fun::init_funcs(&mut patcher);
///         }
///     }
///
///     // As the functions are both FFI and static mut function pointers,
///     // calling them is unsafe.
///     unsafe {
///         let val = fun::first(1, 2);
///         fun::second(val, 0, 17, std::ptr::null_mut());
///     }
/// }
/// ```
#[macro_export]
macro_rules! whack_funcs {
    (stdcall, $init_fn:ident, $base:expr, $($addr:expr => $name:ident($($args:tt)*) $(-> $ret:ty)*;)*) => {
        $(whack_fn!(pub $name($($args)*) $(-> $ret)*);)*
        #[cold]
        pub unsafe fn $init_fn(patch: &mut $crate::ModulePatcher) {
            unsafe fn init(base: usize, heap: &mut $crate::platform::ExecutableHeap) {
                let diff = base - $base;
                let mut buf = $crate::platform::FuncAssembler::new();
                $(whack_fnwrap_write!(true, $addr as usize, buf, diff, [$($args)*]);)*
                let funcs = buf.write(heap) as usize;
                $(whack_fnwrap_finish!($name, buf, funcs);)*
            }
            patch.add_init_fn(init);
        }
    };
    ($init_fn:ident, $base:expr, $($addr:expr => $name:ident($($args:tt)*) $(-> $ret:ty)*;)*) => {
        $(whack_fn!(pub $name($($args)*) $(-> $ret)*);)*
        #[cold]
        pub unsafe fn $init_fn(patch: &mut $crate::ModulePatcher) {
            unsafe fn init(base: usize, heap: &mut $crate::platform::ExecutableHeap) {
                let diff = base - $base;
                let mut buf = $crate::platform::FuncAssembler::new();
                $(whack_fnwrap_write!(false, $addr as usize, buf, diff, [$($args)*]);)*
                let funcs = buf.write(heap) as usize;
                $(whack_fnwrap_finish!($name, buf, funcs);)*
            }
            patch.add_init_fn(init);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_fnwrap_write {
    ($is_stdcall:expr, $addr:expr, $buf:expr, $diff:expr, [$($args:tt)*]) => {
        $buf.new_fnwrap();
        whack_name_args!([fnwrap, $is_stdcall, $addr, $buf], [$([$args])*]);
        $buf.finish_fnwrap($addr.wrapping_add($diff), $is_stdcall);
    }
}

/// Updates function pointers so they point to the exec memory which was just generated.
/// `buf.next_address` should just give next function offset every time
#[macro_export]
#[doc(hidden)]
macro_rules! whack_fnwrap_finish {
    ($name:ident, $buf:expr, $funcs:expr) => {
        $name.0 = $funcs + $buf.next_offset();
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_fn {
    (pub $name:ident($($args:tt)*)) => {
        whack_fn!(pub $name($($args)*) -> ());
    };
    (pub $name:ident($($args:tt)*) -> $ret:ty) => {
        whack_name_args!([fndecl, $name, $ret], [$([$args])*]);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_fndecl {
    ($name:ident, $ret:ty, $([$args:ty])*) => {
        #[allow(non_upper_case_globals)]
        pub static mut $name: $crate::Func<extern fn($($args),*) -> $ret> =
            $crate::Func(0, ::std::marker::PhantomData);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_fnwrap_write_separated {
    ($is_stdcall:expr, $addr:expr, $buf:expr, $([$argloc:ident ~ $argpos:expr])*) => {{
        $(whack_fnwrap_write_arg!($is_stdcall, $addr, $buf, [$argloc ~ $argpos]);)*
    }}
}

#[macro_export]
#[doc(hidden)]
macro_rules! whack_fnwrap_write_arg {
    ($is_stdcall:expr, $addr:expr, $buf:expr, [stack ~ $apos:expr]) => {
        $buf.stack($apos);
    };
    ($is_stdcall:expr, $addr:expr, $buf:expr, [$aloc:ident ~ $apos:expr]) => {
        $buf.register(reg_id!($aloc));
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
macro_rules! whack_name_args_recurse {
    // @ stack
    (nope, $imp_stack_pos:expr, [$($other:tt),*],
        [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
            [$([$oki @ $imploc($impp): $okt])* [$next_id @ stack($pos): $next_ty]],
            [$($rest_args)*], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
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
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
            [$([$oki @ $imploc($impp): $okt])* [$next_id @ stack($pos): $next_ty]],
            [], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ stack($pos:expr) $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
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
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
            [$([$oki @ $imploc($impp): $okt])* [$next_id @ $loc(0): $next_ty]],
            [$($rest_args)*], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ $loc:ident $next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
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
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
            [$([$oki @ $imploc($impp): $okt])* [$next_id @ $loc(0): $next_ty]],
            [], [$($rest_id),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [@ $loc:ident $next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos, [$($other),*],
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
        whack_name_args_recurse!(nope, $imp_stack_pos + 1, [$($other),*],
            [$([$oki @ $okl($okp) / $imploc($impp): $okt])*
                [$next_id @ $next_loc($nextp) / stack($imp_stack_pos): $next_ty]],
            [$($rest_args)*], [$($rest_id),*], [$($rest_loc($rest_pos)),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [$next_ty:ty, $($rest_args:tt)+],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos + 1, [$($other),*],
            [$([$oki @ $okl($okp): $okt])* [$next_id @ stack($imp_stack_pos): $next_ty]],
            [$($rest_args)*], [$($rest_id),*]);
    };
    // Last arg without @location
    (nope, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*],
        [$next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*],
        [$next_loc:ident($nextp:expr), $($rest_loc:ident($rest_pos:expr)),*]) =>
    {
        whack_name_args_recurse!(nope, $imp_stack_pos + 1,
            [$($other),*],
            [$([$oki @ $okl($okp) / $imploc($impp): $okt])*
                [$next_id @ $next_loc($nextp) / stack($imp_stack_pos): $next_ty]],
            [], [$($rest_id),*], [$($rest_loc($rest_pos)),*]);
    };
    (yup, $imp_stack_pos:expr, [$($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*],
        [$next_ty:ty],
        [$next_id:ident, $($rest_id:ident),*]) =>
    {
        whack_name_args_recurse!(yup, $imp_stack_pos + 1, [$($other),*],
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
    (nope, $imp_stack_pos:expr, [fnwrap, $($other:tt),*],
     [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*], [],
     [$($rest:ident),*], [$($rest_loc:ident($rest_pos:expr)),*]) => {
        whack_fnwrap_write_separated!($($other,)* $([$okl ~ $okp])*);
    };
    (yup, $imp_stack_pos:expr, [fnwrap, $($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*], [],
     [$($rest:ident),*]) => {
        whack_fnwrap_write_separated!($($other,)* $([$okl ~ $okp])*);
    };
    (nope, $imp_stack_pos:expr, [fndecl, $($other:tt),*],
     [$([$oki:ident @ $okl:ident($okp:expr) / $imploc:ident($impp:expr): $okt:ty])*], [],
     [$($rest:ident),*], [$($rest_loc:ident($rest_pos:expr)),*]) => {
        whack_fndecl!($($other,)* $([$okt])*);
    };
    (yup, $imp_stack_pos:expr, [fndecl, $($other:tt),*], [$([$oki:ident @ $okl:ident($okp:expr): $okt:ty])*], [],
     [$($rest:ident),*]) => {
        whack_fndecl!($($other,)* $([$okt])*);
    };
}
