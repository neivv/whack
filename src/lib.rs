#![feature(link_args, asm)]
#[link_args = "-static-libgcc"]
extern {}
extern crate byteorder;
extern crate libc;
extern crate kernel32;
extern crate winapi;
extern crate rust_win32error;
#[macro_use(defer)]
extern crate scopeguard;
extern crate smallvec;

#[macro_use]
mod macros;
#[macro_use]
#[cfg(target_arch = "x86")]
#[path = "macros_x86.rs"]
mod macros_ex;
#[macro_use]
#[cfg(target_arch = "x86_64")]
#[path = "macros_x86_64.rs"]
mod macros_ex;
mod pe;

#[cfg(windows)]
mod win_common;
#[cfg(target_arch = "x86")]
#[path = "x86.rs"]
#[doc(hidden)]
pub mod platform;
#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
#[doc(hidden)]
pub mod platform;

pub use macros::{AddressHook, AddressHookClosure, ExportHook, ExportHookClosure};

use std::{ops, mem};
use std::ffi::{OsStr, OsString};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, MutexGuard, Mutex, Weak};

struct PatchHistory {
    ty: platform::PatchType,
    // Used if the patch was applied by `patch_modules`,
    // so that all patches caused by one call can be removed.
    // 0 otherwise.
    // Also (currently) !0 means that it's an internal
    // library loading hook.
    all_modules_id: u32,
}

/// A 'handle' to a patch. Allows disabling/re-enabling it at will.
/// Also allows to permamently delete the patch, which may free a bit
/// of memory that may have been allocated for the patch to work.
///
/// Note that the patch handle is not unique, and the user needs to
/// keep track of `PatchManager` that had actually created the patch
/// in order to use it.
pub struct Patch(PatchEnum);

enum PatchEnum {
    Single(Weak<PatchHistory>),
    AllModules(Weak<u32>),
}

/// The main patching structure.
///
/// Keeps track of applied patches and provides a heap which the patches
/// will use to allocate executable memory as needed.
/// As this structure would have to be wrapped in a `Mutex` in most of
/// the use cases, it is done always to allow additional features such
/// as convenience functions for doing patches on library loading.
pub struct Patcher {
    mutex: Arc<Mutex<PatcherState>>,
}

/// Allows actually patching the current process.
///
/// Accessible with `Patcher.patch()`, see `Patcher` for more information.
#[must_use]
pub struct ActivePatcher<'a> {
    parent: &'a Patcher,
    state: MutexGuard<'a, PatcherState>,
}

struct PatcherState {
    // The string is module's name (TODO: It should be normalized).
    patches: Vec<(Option<OsString>, Vec<Arc<PatchHistory>>)>,
    disabled_patches: Vec<(Option<OsString>, Vec<Arc<PatchHistory>>)>,
    exec_heap: platform::ExecutableHeap,
    library_load_hooks: Vec<Arc<PatchHistory>>,
    automatic_library_patches: Vec<(Box<Fn(AnyModulePatch)>, Arc<u32>)>,
    next_all_modules_id: u32,
}

impl Patcher {
    /// Creates a new `Patcher`.
    pub fn new() -> Patcher {
        Patcher {
            mutex: Arc::new(Mutex::new(PatcherState::new())),
        }
    }

    fn clone_ref(&self) -> Patcher {
        Patcher {
            mutex: self.mutex.clone(),
        }
    }

    /// Locks the mutex, allowing to actually apply patches.
    ///
    /// Returns `Err` if the locking fails.
    ///
    /// NOTE: The patcher should be dropped before executing non-patching related code,
    /// especially if there are hooks that can lead to additional patches. Otherwise a
    /// deadlock will occur. One possible issue is caused by using `patch_modules`, and
    /// loading another library while the `Patcher` is locked.
    pub fn lock(&self) -> Result<ActivePatcher, ()> {
        let guard = try!(self.mutex.lock().map_err(|_| ()));
        Ok(ActivePatcher {
            parent: self,
            state: guard
        })
    }
}

impl PatcherState {
    fn new() -> PatcherState {
        PatcherState {
            patches: Vec::new(),
            disabled_patches: Vec::new(),
            exec_heap: platform::ExecutableHeap::new(),
            library_load_hooks: Vec::new(),
            automatic_library_patches: Vec::new(),
            next_all_modules_id: 1,
        }
    }
}

/// Meant to be used with PatcherState.patches
fn find_or_create_mod_patch_vec<'a>(patches: &'a mut Vec<(Option<OsString>, Vec<Arc<PatchHistory>>)>,
                                    name: Option<&OsStr>) -> &'a mut Vec<Arc<PatchHistory>> {
    let position = match patches.iter_mut()
        .position(|&mut (ref a, _)| a.as_ref().map(|x| x.as_os_str()) == name) {
        Some(p) => p,
        None => {
            patches.push((name.map(|x| x.to_os_string()), Vec::new()));
            patches.len() - 1
        }
    };
    &mut patches[position].1
}

fn unprotect_module(module: &Option<OsString>) -> (usize, platform::MemoryProtection) {
    let handle = match *module {
        None => platform::exe_handle(),
        Some(ref lib) => platform::library_handle(lib.as_ref()),
    };
    (handle as usize, platform::MemoryProtection::new(handle))
}

fn merge_patchvec(to: &mut Vec<(Option<OsString>, Vec<Arc<PatchHistory>>)>,
                  source: Vec<(Option<OsString>, Vec<Arc<PatchHistory>>)>)
{
    for (module, patches) in source {
        if let Some(pair) = to.iter_mut().find(|&&mut (ref m, _)| *m == module) {
            pair.1.extend(patches);
            continue;
        }
        to.push((module, patches));
    }
}

impl<'a> ActivePatcher<'a> {
    pub unsafe fn patch_exe<P: FnMut(ModulePatch)>(&mut self, mut closure: P) {
        let exe = platform::exe_handle();
        let _protection = platform::MemoryProtection::new(exe);
        let state = &mut *self.state;
        closure(ModulePatch {
            parent_patches: find_or_create_mod_patch_vec(&mut state.patches, None),
            exec_heap: &mut state.exec_heap,
            automatic_library_patches: &state.automatic_library_patches,
            base: exe as usize,
        });
    }

    pub unsafe fn patch_exe_with_base<P: FnMut(ModulePatchWithBase)>(&mut self, base: usize, mut closure: P) {
        self.patch_exe(|patch| {
            closure(ModulePatchWithBase {
                patch: patch,
                expected_base: base,
            });
        });
    }

    /// Allows patching a library. The closure is called with a `ModulePatch`,
    /// which is be used to apply the patches.
    pub unsafe fn patch_library<P, S>(&mut self, lib: S, mut closure: P)
    where P: FnMut(ModulePatch),
          S: AsRef<OsStr>,
    {
        let lib_handle = platform::library_handle(lib.as_ref());
        let _protection = platform::MemoryProtection::new(lib_handle);
        let state = &mut *self.state;
        closure(ModulePatch {
            parent_patches: find_or_create_mod_patch_vec(&mut state.patches, Some(lib.as_ref())),
            exec_heap: &mut state.exec_heap,
            automatic_library_patches: &state.automatic_library_patches,
            base: lib_handle as usize,
        });
    }

    pub unsafe fn patch_library_with_base<P: FnMut(ModulePatchWithBase)>(&mut self, lib: &str, base: usize, mut closure: P) {
        self.patch_library(lib, |patch| {
            closure(ModulePatchWithBase {
                patch: patch,
                expected_base: base,
            });
        });
    }

    /// Applies patches of `closure` for the executable itself and all currently
    /// loaded libraries, and hooks system's library loading, applying the patches
    /// whenever a new library is loaded.
    ///
    /// Returns a patch that can be used to control both the library loading hook
    /// and any hooks that have been applied in `closure`. (
    pub fn patch_modules<P: Fn(AnyModulePatch) + 'static>(&mut self, closure: P) -> Patch {
        fn make_patch<'a>(this: &'a mut PatcherState,
                                 name: Option<&OsStr>,
                                 addr: platform::LibraryHandle,
                                 uid: u32
                                ) -> AnyModulePatch<'a> {
            AnyModulePatch {
                parent_patches: find_or_create_mod_patch_vec(&mut this.patches, name),
                base: addr as usize,
                all_modules_id: uid,
                exec_heap: &mut this.exec_heap,
            }
        }

        // TODO: Allow applying *a lot* of patches to every module.
        assert!(self.state.next_all_modules_id != u32::max_value());
        let patch_uid = self.state.next_all_modules_id;
        self.state.next_all_modules_id += 1;

        let apply_library_patches = self.state.library_load_hooks.is_empty();
        {
            let exe = platform::exe_handle();
            let _protection = platform::MemoryProtection::new(exe);
            closure(make_patch(&mut *self.state, None, exe, patch_uid));
            if apply_library_patches {
                let patch = make_patch(&mut *self.state, None, exe, !0);
                platform::apply_library_loading_hook(self.parent, patch);
            }
        }
        platform::for_libraries(|name, handle| {
            let _protection = platform::MemoryProtection::new(handle);
            closure(make_patch(&mut *self.state, Some(name), handle, patch_uid));
            if apply_library_patches {
                let patch = make_patch(&mut *self.state, Some(name), handle, !0);
                platform::apply_library_loading_hook(self.parent, patch);
            }
        }).unwrap();
        let arc = Arc::new(patch_uid);
        let weak = Arc::downgrade(&arc);
        self.state.automatic_library_patches.push((Box::new(closure), arc));
        Patch(PatchEnum::AllModules(weak))
    }

    /// Hackish way to support weird calling conventions that some callbacks may require.
    /// (Or fastcall ._.)
    ///
    /// Returns a wrapper that accepts calling convetion specified by `_hook`, calling
    /// `target`. Only unsafe function pointers are accepted.
    pub fn custom_calling_convention<H>(&mut self, _hook: H, target: H::Fnptr) -> *const u8
    where H: AddressHook,
    {
        unsafe { _hook.custom_calling_convention(target, &mut self.state.exec_heap) }
    }

    /// Unapplies all patches.
    ///
    /// Use `repatch()` to reapply them.
    pub unsafe fn unpatch(&mut self) {
        for &mut (ref module, ref mut patches) in self.state.patches.iter_mut() {
            let (base, _protection) = unprotect_module(module);
            for patch in patches.iter_mut() {
                patch.ty.disable(base);
            }
        }
        let patches = mem::replace(&mut self.state.patches, Vec::new());
        merge_patchvec(&mut self.state.disabled_patches, patches);
    }

    /// Reapplies all patches that were previously removed with `unpatch()`.
    pub unsafe fn repatch(&mut self) {
        for &mut (ref module, ref mut patches) in self.state.disabled_patches.iter_mut() {
            let (base, _protection) = unprotect_module(module);
            for patch in patches.iter_mut() {
                patch.ty.enable(base);
            }
        }
        let patches = mem::replace(&mut self.state.disabled_patches, Vec::new());
        merge_patchvec(&mut self.state.patches, patches);
    }
}

/// A patcher which can patch any module.
///
/// Allows only doing import/export hooks.
pub struct AnyModulePatch<'a> {
    parent_patches: &'a mut Vec<Arc<PatchHistory>>,
    exec_heap: &'a mut platform::ExecutableHeap,
    base: usize,
    all_modules_id: u32,
}

pub struct ModulePatch<'a> {
    parent_patches: &'a mut Vec<Arc<PatchHistory>>,
    exec_heap: &'a mut platform::ExecutableHeap,
    /// Hackish solution for platform::hook_new_library
    automatic_library_patches: &'a Vec<(Box<Fn(AnyModulePatch)>, Arc<u32>)>,
    base: usize,
}

pub struct ModulePatchWithBase<'a> {
    patch: ModulePatch<'a>,
    expected_base: usize
}

impl<'a> AnyModulePatch<'a> {
    /// Hooks current module's imported function by editing module's
    /// import table.
    ///
    /// If the module doesn't import such function, `None` is returned.
    ///
    /// `target` can be acquired from casting a function pointer with
    /// correct signature to `usize`. The caller must take care to
    /// pass a hook with correct signature/calling convention.
    pub fn import_hook_closure<H, T>(&mut self, dll: &[u8], _hook: H, target: T) -> Option<Patch>
    where H: ExportHookClosure<T>,
    {
        let func = H::default_export();
        match unsafe { platform::import_hook::<H, T>(self.base, dll, func, target, self.exec_heap) } {
            Some(ty) => {
                let patch = Arc::new(PatchHistory {
                    ty: ty,
                    all_modules_id: self.all_modules_id,
                });
                unsafe { patch.ty.enable(self.base); }
                let weak = Arc::downgrade(&patch);
                self.parent_patches.push(patch);
                Some(Patch(PatchEnum::Single(weak)))
            }
            None => None,
        }
    }

    /// Hooks current module's imported function by editing module's
    /// import table.
    ///
    /// If the module doesn't import such function, `None` is returned.
    ///
    /// Hooks to an `unsafe fn`, which doesn't take reference to the original function.
    /// For hooking with ability to call original function, use `import_hook_opt`,
    /// For hooking to a safe function, use `import_hook_closure`.
    pub fn import_hook<H>(&mut self, dll: &[u8], _hook: H, target: H::Fnptr) -> Option<Patch>
    where H: ExportHook,
    {
        _hook.import(self, dll, target)
    }


    /// Hooks current module's imported function by editing module's
    /// import table.
    ///
    /// If the module doesn't import such function, `None` is returned.
    ///
    /// Hooks to an `unsafe fn`, which takes reference to the original function.
    /// For hooking without ability to call original function, use `import_hook`,
    /// for hooking to a safe function, use `import_hook_closure`.
    pub fn import_hook_opt<H>(&mut self, dll: &[u8], _hook: H, target: H::OptFnptr) -> Option<Patch>
    where H: ExportHook,
    {
        _hook.import_opt(self, dll, target)
    }
}

impl<'a> ModulePatch<'a> {
    /// Hooks a function, replacing it with `target`.
    pub unsafe fn hook_closure<H, T>(&mut self, _hook: H, target: T) -> Patch
    where H: AddressHookClosure<T> {
        self.hook_closure_internal(false, _hook, target)
    }
    /// Public only for call hooks
    #[doc(hidden)]
    pub unsafe fn hook_closure_internal<H, T>(&mut self, preserve_regs: bool, _hook: H, target: T) -> Patch
    where H: AddressHookClosure<T> {
        let ty = platform::jump_hook::<H, T>(self.base, target, self.exec_heap, preserve_regs);
        let patch = Arc::new(PatchHistory {
            ty: ty,
            all_modules_id: 0,
        });
        patch.ty.enable(self.base);
        let weak = Arc::downgrade(&patch);
        self.parent_patches.push(patch);
        Patch(PatchEnum::Single(weak))
    }

    pub unsafe fn hook<H>(&mut self, _hook: H, target: H::Fnptr) -> Patch
    where H: AddressHook,
    {
        _hook.hook(self, target)
    }

    pub unsafe fn hook_opt<H>(&mut self, _hook: H, target: H::OptFnptr) -> Patch
    where H: AddressHook,
    {
        _hook.hook_opt(self, target)
    }

    pub unsafe fn call_hook<H>(&mut self, _hook: H, target: H::Fnptr) -> Patch
    where H: AddressHook,
    {
        _hook.call_hook(self, target)
    }

    fn any_module_downgrade(&mut self, all_modules_id: u32) -> AnyModulePatch {
        AnyModulePatch {
            parent_patches: self.parent_patches,
            exec_heap: self.exec_heap,
            base: self.base,
            all_modules_id: all_modules_id
        }
    }

    pub fn base(&self) -> usize {
        self.base
    }
}

/// An exported function, identified either by its name or ordinal.
pub enum Export<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
}

impl<'a> ModulePatchWithBase<'a> {
    fn current_base<Addr: ToPointer>(&self, addr: Addr) -> *mut u8 {
        let diff = self.patch.base.overflowing_sub(self.expected_base).0;
        unsafe { mem::transmute(mem::transmute::<_, usize>(addr.ptr()).overflowing_add(diff).0) }
    }

    #[cfg(target_arch = "x86")]
    pub unsafe fn nop<Addr: ToPointer>(&mut self, addr: Addr, len: usize) {
        self.replace(addr, vec![platform::nop(); len])
    }

    pub unsafe fn replace_u32<Addr: ToPointer>(&mut self, addr: Addr, val: u32) {
        let ptr: *mut u32 = mem::transmute(self.current_base(addr));
        *ptr = val;
    }

    pub unsafe fn replace<Addr: ToPointer>(&mut self, addr: Addr, data: Vec<u8>) {
        let ptr = self.current_base(addr);
        let mut i = 0;
        for byte in data.iter() {
            *ptr.offset(i) = *byte;
            i += 1;
        }
    }
}

impl<'a> ops::Deref for ModulePatchWithBase<'a> {
    type Target = ModulePatch<'a>;
    fn deref(&self) -> &ModulePatch<'a> {
        &self.patch
    }
}

impl<'a> ops::DerefMut for ModulePatchWithBase<'a> {
    fn deref_mut(&mut self) -> &mut ModulePatch<'a> {
        &mut self.patch
    }
}

pub trait ToPointer {
    fn ptr(&self) -> *mut u8;
}

impl ToPointer for usize {
    fn ptr(&self) -> *mut u8 {
        unsafe { mem::transmute(*self) }
    }
}

impl<T> ToPointer for *mut T {
    fn ptr(&self) -> *mut u8 {
        unsafe { mem::transmute::<*mut T, *mut u8>(*self) }
    }
}

/// Redirects stderr to a file.
pub unsafe fn redirect_stderr<F: AsRef<Path>>(filename: F) -> bool {
    platform::redirect_stderr(filename.as_ref())
}

#[doc(hidden)]
pub trait HookableAsmWrap {
    type Target; // extern "C" fn(a1_type, a2_type, ...) -> ret
    type OptionalTarget; // fn(a1_type, a2_type, ...) -> Option<ret>
    unsafe fn get_hook_wrapper() -> *const u8;

    // stdcall/etc args, cdecl returns 0
    fn stack_args_count() -> usize;
    // All args
    fn arg_count() -> usize;
    // Hook-specific code in platform::optional_hook
    fn opt_push_args_asm() -> &'static [u8];
    // Casted from the function pointer
    fn opt_hook_intermediate() -> *mut u8;

    fn address() -> usize;
    fn expected_base() -> usize;
}

// This could also be just a vector that gets the dynamic parts of
// actual hook address and intermediate address as input, but having
// everything completely constant should be a bit faster
#[doc(hidden)]
pub struct OptHookWrapper {
    // There is push dword hook_address instruction at beginning of asm wrapper
    // placed in platform::optional_hook
    pub call: &'static [u8],
    pub intermediate_wrapper: *const u8,
    pub exit: &'static [u8],
}

pub struct Variable<T> {
    pub address: usize,
    pub phantom: PhantomData<T>,
}

unsafe impl<T> Sync for Variable<T> { }

impl<T> Variable<T> {
    pub fn new(addr: usize) -> Variable<T> {
        Variable {
            address: addr,
            phantom: PhantomData,
        }
    }
    pub unsafe fn ptr(&self) -> *const T {
        mem::transmute(self.address)
    }
    pub unsafe fn mut_ptr(&self) -> *mut T {
        mem::transmute(self.address)
    }
}

impl<T> ops::Deref for Variable<T> {
    type Target = T;
    fn deref<'a>(&'a self) -> &'a T {
        unsafe { mem::transmute(self.address) }
    }
}

impl<T> ops::DerefMut for Variable<T> {
    fn deref_mut<'a>(&'a mut self) -> &'a mut T {
        unsafe { mem::transmute(self.address) }
    }
}

#[doc(hidden)]
/// A type which wraps a memory address and `Deref`s to `fn(...) -> ...`.
/// `Func` is meant to be created by the `whack_funcs!` macro, and to be used as it were
/// a static mutable function pointer.
pub struct Func<FnPtr>(pub usize, pub PhantomData<FnPtr>);

impl<FnPtr> ops::Deref for Func<FnPtr> {
    type Target = FnPtr;
    fn deref(&self) -> &FnPtr {
        unsafe { mem::transmute(&self.0) }
    }
}
