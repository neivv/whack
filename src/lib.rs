#![feature(link_args, asm)]
#[link_args = "-static-libgcc"]
extern {}
extern crate byteorder;
extern crate lde;
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

mod patch_map;

pub use macros::{AddressHook, AddressHookClosure, ExportHook, ExportHookClosure};

use std::{mem, ops};
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::marker::{PhantomData, Sync};
use std::path::Path;
use std::sync::{Arc, MutexGuard, Mutex, Weak};

use libc::c_void;
use smallvec::SmallVec;

use patch_map::PatchMap;

struct PatchHistory {
    ty: platform::PatchType,
}

// Slightly skecthy as dropping without clearing prev_imports/hook_entry first will leak memory,
// unless the owning Patcher is cleared as well, as that'll free everything from the exec heap.
// Most operations require memory to be unprotected in advance.
struct AllModulesImport {
    library: Cow<'static, [u8]>,
    export: Export<'static>,
    wrapper_code: ::platform::HookWrapCode,
    // This keeps the hook target alive as long as the hook exists.
    #[allow(dead_code)]
    wrapper_target: Box<[u8]>,
    enabled: bool,
    // module, orig_entry, hook_entry (fixed up for this orig_entry)
    prev_imports: Vec<(platform::LibraryHandle, *mut c_void, *mut c_void)>,
}

#[derive(Clone, Copy)]
pub enum OrigFuncCallback {
    None,
    // Just gives a way to call the original function.
    Overwritten(*const u8),
    // Calls original function afterwards.
    Hook(*const u8),
    // For import hooks, allows setting the value once the library is actually loaded.
    ImportHook,
}

/// A 'handle' to a patch. Allows disabling/re-enabling it at will.
/// Also allows to permamently delete the patch, which may free a bit
/// of memory that may have been allocated for the patch to work.
///
/// Note that the patch handle is not unique, and the user needs to
/// keep track of `Patcher` that had actually created the patch
/// in order to use it.
pub struct Patch(PatchEnum);

enum PatchEnum {
    Single(Weak<PatchHistory>),
    AllModulesImport(patch_map::Key),
    Group(Vec<PatchEnum>),
}

impl AllModulesImport {
    fn apply_new(&mut self,
                 module: platform::LibraryHandle,
                 heap: &mut platform::ExecutableHeap) {
        unsafe {
            let addr = platform::import_addr(module, &self.library, &self.export);
            if let Some(addr) = addr {
                let orig = *addr;
                let (hook_entry, _) = self.wrapper_code.write_wrapper(None,
                                                                      heap,
                                                                      Some(orig as *const u8));
                self.prev_imports.push((module, orig as *mut c_void, hook_entry as *mut c_void));
                if self.enabled {
                    *addr = hook_entry as usize;
                }
            }
        }
    }

    fn library_unloaded(&mut self,
                        library: platform::LibraryHandle,
                        heap: &mut platform::ExecutableHeap) {
        for &(_, _, hook_entry) in self.prev_imports.iter().filter(|&&(m, _, _)| m == library) {
            heap.free(hook_entry as *mut u8);
        }
        self.prev_imports.retain(|&(m, _, _)| m != library);
    }

    fn enable(&mut self) {
        if !self.enabled {
            for &(lib, _, hook) in &self.prev_imports {
                unsafe {
                    match platform::import_addr(lib, &self.library, &self.export) {
                        Some(addr) => *addr = hook as usize,
                        None => panic!("Could not enable import hook"),
                    }
                }
            }
            self.enabled = true;
        }
    }

    fn disable(&mut self) {
        if self.enabled {
            for &(lib, orig, _) in &self.prev_imports {
                unsafe {
                    match platform::import_addr(lib, &self.library, &self.export) {
                        Some(addr) => *addr = orig as usize,
                        None => panic!("Could not disable import hook"),
                    }
                }
            }
            self.enabled = false;
        }
    }
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
    sys_patch_count: u32,
    all_module_patches: PatchMap<AllModulesImport>,
}

/// Allows applying patches that modify all currently loaded modules, and ones that will be
/// loaded later.
///
/// Currently those patches are only import hooks.
///
/// Any patches created `AllModulesPatcher` will be enabled once `apply()` is called. If it is
/// skipped, the destructor will enable patches anyways, but `apply()` allows submitting them
/// while disabled, and gives a `Patch` handle for enabling/disabling them all at once.
#[must_use]
pub struct AllModulesPatcher<'a: 'b, 'b> {
    parent: &'b mut ActivePatcher<'a>,
    patches: Vec<(AllModulesImport, patch_map::Key)>,
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
            sys_patch_count: 0,
            all_module_patches: PatchMap::new(),
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


    /// Begin applying patches that affect every module of the process. See `AllModulesPatcher`
    /// for more information.
    pub fn patch_all_modules<'b>(&'b mut self) -> AllModulesPatcher<'a, 'b> {
        AllModulesPatcher {
            parent: self,
            patches: Vec::new(),
        }
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

    pub fn disable_patch(&mut self, patch: &Patch) {
        let mut memprotect_guard = SmallVec::new();
        self.unprotect_patch_memory(&patch.0, &mut memprotect_guard);
        self.disable_patch_internal(&patch.0)
    }

    fn disable_patch_internal(&mut self, patch: &PatchEnum) {
        match *patch {
            PatchEnum::Single(_) => unimplemented!(),
            PatchEnum::AllModulesImport(ref key) => {
                if let Some(patch) = self.state.all_module_patches.get_mut(key) {
                    patch.disable();
                }
            }
            PatchEnum::Group(ref patches) => {
                for patch in patches {
                    self.disable_patch_internal(patch);
                }
            }
        }
    }

    pub fn enable_patch(&mut self, patch: &Patch) {
        let mut memprotect_guard = SmallVec::new();
        self.unprotect_patch_memory(&patch.0, &mut memprotect_guard);
        self.enable_patch_internal(&patch.0)
    }

    fn enable_patch_internal(&mut self, patch: &PatchEnum) {
        match *patch {
            PatchEnum::Single(_) => unimplemented!(),
            PatchEnum::AllModulesImport(ref key) => {
                if let Some(patch) = self.state.all_module_patches.get_mut(key) {
                    patch.enable();
                }
            }
            PatchEnum::Group(ref patches) => {
                for patch in patches {
                    self.enable_patch_internal(patch);
                }
            }
        }
    }

    fn unprotect_patch_memory(&self,
                              patch: &PatchEnum,
                              protections: &mut SmallVec<[(platform::LibraryHandle,
                                                           platform::MemoryProtection); 16]>)
    {
        match *patch {
            PatchEnum::Single(_) => unimplemented!(),
            PatchEnum::AllModulesImport(ref key) => {
                if let Some(patch) = self.state.all_module_patches.get(key) {
                    for &(handle, _, _) in &patch.prev_imports {
                        if !protections.iter().any(|&(x, _)| x == handle) {
                            let protection = platform::MemoryProtection::new(handle);
                            protections.push((handle, protection));
                        }
                    }
                }
            }
            PatchEnum::Group(ref patches) => {
                for patch in patches {
                    self.unprotect_patch_memory(patch, protections);
                }
            }
        }
    }

    /// Unapplies all patches.
    ///
    /// Use `repatch()` to reapply them.
    pub unsafe fn unpatch(&mut self) {
        let state = &mut self.state;
        for &mut (ref module, ref mut patches) in state.patches.iter_mut() {
            let (base, _protection) = unprotect_module(module);
            for patch in patches.iter_mut() {
                patch.ty.disable(base);
            }
        }
        let patches = mem::replace(&mut state.patches, Vec::new());
        merge_patchvec(&mut state.disabled_patches, patches);
        for patch in state.all_module_patches.iter_mut() {
            patch.disable();
        }
    }

    /// Reapplies all patches that were previously removed with `unpatch()`.
    pub unsafe fn repatch(&mut self) {
        let state = &mut self.state;
        for &mut (ref module, ref mut patches) in state.disabled_patches.iter_mut() {
            let (base, _protection) = unprotect_module(module);
            for patch in patches.iter_mut() {
                patch.ty.enable(base);
            }
        }
        let patches = mem::replace(&mut state.disabled_patches, Vec::new());
        merge_patchvec(&mut state.patches, patches);
        for patch in state.all_module_patches.iter_mut() {
            patch.enable();
        }
    }

    fn library_loaded(&mut self, library: platform::LibraryHandle) {
        let state = &mut *self.state;
        for patch in state.all_module_patches.iter_mut() {
            patch.apply_new(library, &mut state.exec_heap);
        }
    }

    fn library_unloaded(&mut self, library: platform::LibraryHandle) {
        let state = &mut *self.state;
        for patch in state.all_module_patches.iter_mut() {
            patch.library_unloaded(library, &mut state.exec_heap);
        }
    }
}

impl<'a: 'b, 'b> AllModulesPatcher<'a, 'b> {
    /// Creates a `Patch` which hooks a function `hook`, exported by `library` by editing every
    /// module's import table.
    ///
    /// This function doesn't require `library` to be loaded. As such, if the library doesn't
    /// actually export `hook`, any errors will not be reported.
    pub fn import_hook_closure<H, T>(&mut self,
                                     library: Cow<'static, [u8]>,
                                     _hook: H,
                                     target: T
                                    ) -> Patch
    where H: ExportHookClosure<T>,
    {
        let wrapper_target = H::write_target_objects(target);
        let patch = AllModulesImport {
            library: library,
            export: H::default_export(),
            wrapper_code: H::wrapper_assembler(wrapper_target.as_ptr())
                .generate_wrapper_code(OrigFuncCallback::ImportHook),
            wrapper_target: wrapper_target,
            enabled: false,
            prev_imports: Vec::new(),
        };
        let key = self.parent.state.all_module_patches.alloc_slot();
        self.patches.push((patch, key.clone()));
        Patch(PatchEnum::AllModulesImport(key))
    }

    /// Same as `import_hook_closure`, but hooks to an `unsafe fn` which doesn't take
    /// reference to the original function.
    pub fn import_hook<H>(&mut self,
                          library: Cow<'static, [u8]>,
                          hook: H,
                          target: H::Fnptr
                          ) -> Patch
    where H: ExportHook,
    {
        // `ExportHook::import` just calls `import_hook_closure()` with a short unsafe {}
        // wrapper. It needs to be defined with a macro as the function signatures are different
        // for each hook.
        hook.import(self, library, target)
    }


    /// Same as `import_hook_closure`, but hooks to an `unsafe fn` which can also call the
    /// original function.
    pub fn import_hook_opt<H>(&mut self,
                              library: Cow<'static, [u8]>,
                              hook: H,
                              target: H::OptFnptr
                             ) -> Patch
    where H: ExportHook,
    {
        hook.import_opt(self, library, target)
    }

    /// Applies and enables the patches which have been created using `AllModulesPatcher`.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply(mut self) -> Patch {
        self.apply_system_patches();
        // Have to do this as actually consuming is not allowed due to Drop impl
        let patches = mem::replace(&mut self.patches, vec![]);
        AllModulesPatcher::apply_patches(self.parent, patches, true)
    }

    /// Applies the patches which have been created using `AllModulesPatcher`, without enabling
    /// them.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply_disabled(mut self) -> Patch {
        self.apply_system_patches();
        let patches = mem::replace(&mut self.patches, vec![]);
        AllModulesPatcher::apply_patches(self.parent, patches, false)
    }

    fn apply_system_patches(&mut self) {
        if self.parent.state.sys_patch_count == 0 {
            platform::apply_library_loading_hook(self.parent.parent, self);
        }
        self.parent.state.sys_patch_count += 1;
    }

    fn apply_patches(parent: &mut ActivePatcher,
                     mut patches: Vec<(AllModulesImport, patch_map::Key)>,
                     enable: bool
                    ) -> Patch
    {
        if enable {
            for &mut (ref mut patch, _) in &mut patches {
                patch.enable();
            }
        }
        {
            let exe = platform::exe_handle();
            let _protection = platform::MemoryProtection::new(exe);
            for &mut (ref mut patch, _) in &mut patches {
                patch.apply_new(exe, &mut parent.state.exec_heap);
            }
        }
        platform::for_libraries(|_, handle| {
            let _protection = platform::MemoryProtection::new(handle);
            for &mut (ref mut patch, _) in &mut patches {
                patch.apply_new(handle, &mut parent.state.exec_heap);
            }
        }).unwrap();
        let group = patches.iter()
            .map(|&(_, ref key)| PatchEnum::AllModulesImport(key.clone()))
            .collect();

        for (patch, key) in patches {
            parent.state.all_module_patches.assign(key, patch);
        }
        Patch(PatchEnum::Group(group))
    }
}

impl<'a: 'b, 'b> Drop for AllModulesPatcher<'a, 'b> {
    fn drop(&mut self) {
        // Apply patches if they weren't applied
        if !self.patches.is_empty() {
            self.apply_system_patches();
            let patches = mem::replace(&mut self.patches, vec![]);
            AllModulesPatcher::apply_patches(self.parent, patches, true);
        }
    }
}

/// A patcher for a specific module.
///
/// Allows module-specific operations which depend on base address, that is, hooking.
///
/// Created by `Patcher::patch_exe()` and `Patcher::patch_library()`.
pub struct ModulePatch<'a> {
    parent_patches: &'a mut Vec<Arc<PatchHistory>>,
    exec_heap: &'a mut platform::ExecutableHeap,
    /// Hackish solution for platform::hook_new_library
    base: usize,
}


/// A patcher for a specific module with an excepted base address.
///
/// Has functionality to apply nop and constant patches to specific addresses.
///
/// Created by `Patcher::patch_exe_with_base()` and `Patcher::patch_library_with_base()`.
///
/// For convenience, `Deref`s to `ModulePatch`.
pub struct ModulePatchWithBase<'a> {
    patch: ModulePatch<'a>,
    expected_base: usize
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
        });
        patch.ty.enable(self.base);
        let weak = Arc::downgrade(&patch);
        self.parent_patches.push(patch);
        Patch(PatchEnum::Single(weak))
    }

    /// Applies a hook to a function.
    ///
    /// The original function will not be called afterwards. To apply a non-modifying hook, use
    /// `call_hook()` or `hook_opt()`.
    pub unsafe fn hook<H>(&mut self, _hook: H, target: H::Fnptr) -> Patch
    where H: AddressHook,
    {
        _hook.hook(self, target)
    }

    /// Applies a hook to a function, with possibility to call the original function during hook.
    pub unsafe fn hook_opt<H>(&mut self, _hook: H, target: H::OptFnptr) -> Patch
    where H: AddressHook,
    {
        _hook.hook_opt(self, target)
    }

    /// Applies a hook to a function, without replacing any of the original code.
    ///
    /// This hook cannot return values.
    pub unsafe fn call_hook<H>(&mut self, _hook: H, target: H::Fnptr) -> Patch
    where H: AddressHook,
    {
        _hook.call_hook(self, target)
    }

    /// Retreives the current base address of the module.
    #[inline]
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
    #[inline]
    fn deref_mut(&mut self) -> &mut ModulePatch<'a> {
        &mut self.patch
    }
}

pub trait ToPointer {
    fn ptr(&self) -> *mut u8;
}

impl ToPointer for usize {
    fn ptr(&self) -> *mut u8 {
        *self as *mut u8
    }
}

impl<T> ToPointer for *mut T {
    fn ptr(&self) -> *mut u8 {
        *self as *mut u8
    }
}

/// Redirects stderr to a file.
pub unsafe fn redirect_stderr<F: AsRef<Path>>(filename: F) -> bool {
    platform::redirect_stderr(filename.as_ref())
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
