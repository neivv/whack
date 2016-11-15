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

type InitFn = unsafe fn(usize, &mut platform::ExecutableHeap);

pub use macros::{AddressHook, AddressHookClosure, ExportHook, ExportHookClosure};

use std::{mem, ops, ptr};
use std::borrow::Cow;
use std::ffi::OsStr;
use std::marker::{PhantomData, Sync};
use std::path::Path;
use std::sync::{Arc, MutexGuard, Mutex};

use libc::c_void;
use smallvec::SmallVec;

use patch_map::PatchMap;

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

enum ModulePatchType {
    Hook(HookPatch),
    Data(SmallVec<[u8; 16]>, SmallVec<[u8; 16]>),
}

struct HookPatch {
    wrapper_code: platform::HookWrapAssembler,
    // This keeps the hook target alive as long as the hook exists.
    #[allow(dead_code)]
    wrapper_target: Box<[u8]>,
    wrapper: Option<*const u8>,
    orig_ins_len: usize,
    // Is this a replacing hook or just a detour
    replacing: bool,
}

struct ModulePatch {
    variant: ModulePatchType,
    library: Option<Arc<platform::LibraryName>>,
    // Relative from base address
    address: usize,
    // Will the patch will get activated whenever the relevant module is loaded
    enabled: bool,
    // Is the patch is actually applied to a module (hooks have allocated their wrapper code)
    active: bool,
}

fn library_name_to_handle_opt(val: &Option<Arc<platform::LibraryName>>)
    -> Option<platform::LibraryHandle> {
    match *val {
        Some(ref s) => platform::library_name_to_handle(s),
        None => Some(platform::exe_handle()),
    }
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
    Regular(patch_map::Key),
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

impl HookPatch {
    fn free_wrapper(&mut self, heap: &mut platform::ExecutableHeap) {
        if let Some(wrapper) = self.wrapper {
            // Beh, should have better system than this dumb orig_ins_len stuff.
            unsafe { heap.free(wrapper.offset(0 - self.orig_ins_len as isize) as *mut u8); }
            self.wrapper = None;
        }
    }

    unsafe fn revert(&mut self, address: *mut u8, heap: &mut platform::ExecutableHeap) {
        if let Some(wrapper) = self.wrapper {
            let orig_ins = wrapper.offset(0 - self.orig_ins_len as isize);
            std::ptr::copy_nonoverlapping(orig_ins, address, self.orig_ins_len);
        }
        self.free_wrapper(heap);
    }
}

impl ModulePatch {
    // Assumes that library is the module patches need to be applied to
    unsafe fn library_loaded(&mut self,
                             library: platform::LibraryHandle,
                             heap: &mut platform::ExecutableHeap) {
        if self.enabled && !self.active {
            self.activate(library, heap);
        }
    }

    // Assumes that library is the module patches need to be applied to
    fn library_unloaded(&mut self, heap: &mut platform::ExecutableHeap) {
        match self.variant {
            ModulePatchType::Hook(ref mut hook) => hook.free_wrapper(heap),
            ModulePatchType::Data(_, _) => (),
        }
        self.active = false;
    }

    // If the module wasn't currently loaded, this will make the patch to apply on load.
    fn mark_enabled(&mut self) {
        self.enabled = true;
    }

    unsafe fn activate(&mut self,
                       handle: platform::LibraryHandle,
                       heap: &mut platform::ExecutableHeap) {
        if !self.active {
            let address = (handle as usize + self.address) as *const u8;
            match self.variant {
                ModulePatchType::Hook(ref mut hook) => {
                    let orig = match hook.replacing {
                        true => OrigFuncCallback::Overwritten(address),
                        false => OrigFuncCallback::Hook(address),
                    };
                    let (wrapper, orig_ins_len) = hook.wrapper_code.generate_wrapper_code(orig)
                        .write_wrapper(Some(address), heap, None);
                    platform::write_jump(address as *mut u8, wrapper);
                    hook.wrapper = Some(wrapper);
                    hook.orig_ins_len = orig_ins_len;
                }
                ModulePatchType::Data(ref data, ref mut previous) => {
                    ptr::copy_nonoverlapping(address, previous.as_mut_ptr(), data.len());
                    ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());
                }
            }
            self.active = true;
        }
    }

    unsafe fn enable(&mut self,
                     handle: platform::LibraryHandle,
                     heap: &mut platform::ExecutableHeap) {
        if !self.enabled {
            self.activate(handle, heap);
            self.enabled = true;
        }
    }

    unsafe fn disable(&mut self,
                      handle: Option<platform::LibraryHandle>,
                      heap: &mut platform::ExecutableHeap) {
        if self.active {
            if let Some(handle) = handle {
                let address = (handle as usize + self.address) as *mut u8;
                match self.variant {
                    ModulePatchType::Hook(ref mut hook) => {
                        hook.revert(address, heap);
                    }
                    ModulePatchType::Data(_, ref previous) => {
                        ptr::copy_nonoverlapping(previous.as_ptr(), address, previous.len());
                    }
                }
            } else {
                match self.variant {
                    ModulePatchType::Hook(ref mut hook) => hook.free_wrapper(heap),
                    ModulePatchType::Data(_, _) => (),
                }
            }
            self.active = false;
        }
        self.enabled = false;
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
    patches: PatchMap<ModulePatch>,
    patch_groups: Vec<PatchGroup>,
    exec_heap: platform::ExecutableHeap,
    sys_patch_count: u32,
    all_module_patches: PatchMap<AllModulesImport>,
}

/// Groups of patches that apply to a single module.
struct PatchGroup {
    library: Option<Arc<platform::LibraryName>>,
    patches: Vec<patch_map::Key>,
    init_funcs: Vec<InitFn>,
    library_loaded: bool,
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

/// Allows applying patches that modify a single module.
///
/// If the module is a library which has not been loaded, or a library that gets unloaded
/// and loaded again, any patches will get automatically applied on each load.
///
/// Any patches created `ModulePatcher` will be enabled once `apply()` is called. If it is
/// skipped, the destructor will enable patches anyways, but `apply()` allows submitting them
/// while disabled, and gives a `Patch` handle for enabling/disabling them all at once.
#[must_use]
pub struct ModulePatcher<'a: 'b, 'b> {
    parent: &'b mut ActivePatcher<'a>,
    patches: Vec<(ModulePatch, patch_map::Key)>,
    library: Option<Arc<platform::LibraryName>>,
    init_fns: Vec<InitFn>,
    excepted_base: usize,
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
            patches: PatchMap::new(),
            patch_groups: Vec::new(),
            exec_heap: platform::ExecutableHeap::new(),
            sys_patch_count: 0,
            all_module_patches: PatchMap::new(),
        }
    }
}

impl<'a> ActivePatcher<'a> {
    /// Begins patching the executable.
    ///
    /// Call methods of the returned `ModulePatcher` to apply hooks.
    /// Applying constant/nop patches requires specifying `excepted_base`, otherwise it can
    /// be 0.
    pub fn patch_exe<'b>(&'b mut self, excepted_base: usize) -> ModulePatcher<'a, 'b> {
        ModulePatcher {
            parent: self,
            patches: Vec::new(),
            init_fns: Vec::new(),
            library: None,
            excepted_base: excepted_base,
        }
    }

    /// Begins patching a library
    ///
    /// Call methods of the returned `ModulePatcher` to apply hooks.
    /// Applying constant/nop patches requires specifying `excepted_base`, otherwise it can
    /// be 0.
    pub fn patch_library<'b, T>(&'b mut self,
                                library: T,
                                excepted_base: usize
                                ) -> ModulePatcher<'a, 'b>
    where T: AsRef<OsStr>
    {
        ModulePatcher {
            parent: self,
            patches: Vec::new(),
            init_fns: Vec::new(),
            library: Some(Arc::new(platform::library_name(library))),
            excepted_base: excepted_base,
        }
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
    ///
    /// # Examples
    /// ```rust
    /// #[macro_use] extern crate whack;
    /// extern crate libc;
    ///
    /// use libc::c_void;
    ///
    /// // Addresses aren't relevant here, there just isn't a specialized macro for
    /// // `custom_calling_convention`.
    /// # #[cfg(target_arch = "x86")]
    /// declare_hooks!(0,
    ///     0 => fastcall_4_args(@ecx u32, @edx u32, *const u8, *mut u8) -> u32;
    /// );
    ///
    /// // Using thread_local! for simplicity, but `Patcher` internally uses thread-safe mutexes
    /// // regardless.
    /// thread_local!(static PATCHER: whack::Patcher = whack::Patcher::new());
    ///
    /// fn target(a1: u32, a2: u32, a3: *const u8, a4: *mut u8) -> u32 {
    ///     unsafe {
    ///         *a4 = *a3;
    ///     }
    ///     a1 + a2 * 2
    /// }
    ///
    /// // A function taking two ints and a function pointer to fastcall.
    /// unsafe fn ffi_function(a: u32, b: u32, c: *mut c_void) {
    ///     // ...
    /// }
    ///
    /// # #[cfg(target_arch = "x86")]
    /// fn main() {
    ///     let fastcall_ptr = PATCHER.with(|patcher| {
    ///         let mut patcher = patcher.lock().unwrap();
    ///         unsafe {
    ///             patcher.custom_calling_convention(fastcall_4_args, target)
    ///         }
    ///     });
    ///     unsafe {
    ///         ffi_function(1, 2, fastcall_ptr as *mut c_void);
    ///     }
    /// }
    ///
    /// # #[cfg(not(target_arch = "x86"))]
    /// # fn main() {}
    /// ```
    pub unsafe fn custom_calling_convention<H>(&mut self, _hook: H, target: H::Fnptr) -> *const u8
    where H: AddressHook,
    {
        _hook.custom_calling_convention(target, &mut self.state.exec_heap)
    }

    /// Disables a patch which has been created with this `Patcher`.
    pub unsafe fn disable_patch(&mut self, patch: &Patch) {
        let mut memprotect_guard = SmallVec::new();
        self.unprotect_patch_memory(&patch.0, &mut memprotect_guard);
        self.disable_patch_internal(&patch.0)
    }

    unsafe fn disable_patch_internal(&mut self, patch: &PatchEnum) {
        match *patch {
            PatchEnum::Regular(ref key) => {
                let state = &mut *self.state;
                if let Some(patch) = state.patches.get_mut(key) {
                    // TODO: Kind of inefficient for large patch groups
                    let handle = library_name_to_handle_opt(&patch.library);
                    patch.disable(handle, &mut state.exec_heap);
                }
            }
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

    /// (Re-)Enables a patch which has been created with this `Patcher`.
    ///
    /// Generally, any patches that are created get enabled by default, unless a function such as
    /// `ModulePatcher::apply_disabled` is used.
    pub unsafe fn enable_patch(&mut self, patch: &Patch) {
        let mut memprotect_guard = SmallVec::new();
        self.unprotect_patch_memory(&patch.0, &mut memprotect_guard);
        self.enable_patch_internal(&patch.0)
    }

    unsafe fn enable_patch_internal(&mut self, patch: &PatchEnum) {
        match *patch {
            PatchEnum::Regular(ref key) => {
                let state = &mut *self.state;
                if let Some(patch) = state.patches.get_mut(key) {
                    // TODO: Kind of inefficient for large patch groups
                    match library_name_to_handle_opt(&patch.library) {
                        Some(handle) => patch.enable(handle, &mut state.exec_heap),
                        None => patch.mark_enabled(),
                    }
                }
            }
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
        let add_handle_if_needed = |protections: &mut SmallVec<[(platform::LibraryHandle,
                                                                 platform::MemoryProtection); 16]>,
                                    handle|
        {
            if !protections.iter().any(|&(x, _)| x == handle) {
                let protection = platform::MemoryProtection::new(handle);
                protections.push((handle, protection));
            }
        };
        match *patch {
            PatchEnum::Regular(ref key) => {
                if let Some(handle) = self.state.patches.get(key)
                    .and_then(|p| library_name_to_handle_opt(&p.library)) {
                    add_handle_if_needed(protections, handle);
                }
            }
            PatchEnum::AllModulesImport(ref key) => {
                if let Some(patch) = self.state.all_module_patches.get(key) {
                    for &(handle, _, _) in &patch.prev_imports {
                        add_handle_if_needed(protections, handle);
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

    fn unprotect_all_patch_memory(&self)
        -> SmallVec<[(platform::LibraryHandle, platform::MemoryProtection); 16]>
    {
        let state = &*self.state;
        let mut protections =
            SmallVec::<[(platform::LibraryHandle, platform::MemoryProtection); 16]>::new();
        for group in &state.patch_groups {
            if let Some(handle) = library_name_to_handle_opt(&group.library) {
                if !protections.iter().any(|&(x, _)| x == handle) {
                    let protection = platform::MemoryProtection::new(handle);
                    protections.push((handle, protection));
                }
            }
        }
        for patch in state.all_module_patches.iter() {
            for &(handle, _, _) in &patch.prev_imports {
                if !protections.iter().any(|&(x, _)| x == handle) {
                    let protection = platform::MemoryProtection::new(handle);
                    protections.push((handle, protection));
                }
            }
        }
        protections
    }

    /// Disables all patches.
    ///
    /// Warning: This will also disable the internal library loading hooks, and the patches
    /// may not work properly if they are used in any way before calling `repatch`.
    pub unsafe fn unpatch(&mut self) {
        let _protections = self.unprotect_all_patch_memory();
        let state = &mut *self.state;
        for group in &mut state.patch_groups {
            if let Some(handle) = library_name_to_handle_opt(&group.library) {
                for key in &group.patches {
                    if let Some(patch) = state.patches.get_mut(key) {
                        patch.disable(Some(handle), &mut state.exec_heap);
                    }
                }
            } else {
                for key in &group.patches {
                    if let Some(patch) = state.patches.get_mut(key) {
                        patch.disable(None, &mut state.exec_heap);
                    }
                }
            }
        }
        for patch in state.all_module_patches.iter_mut() {
            patch.disable();
        }
    }

    /// Enables every patch that has been associated with this `Patcher`.
    pub unsafe fn repatch(&mut self) {
        let _protections = self.unprotect_all_patch_memory();
        let state = &mut *self.state;
        for group in &mut state.patch_groups {
            if let Some(handle) = library_name_to_handle_opt(&group.library) {
                for key in &group.patches {
                    if let Some(patch) = state.patches.get_mut(key) {
                        patch.enable(handle, &mut state.exec_heap);
                    }
                }
            } else {
                for key in &group.patches {
                    if let Some(patch) = state.patches.get_mut(key) {
                        patch.mark_enabled();
                    }
                }
            }
        }
        for patch in state.all_module_patches.iter_mut() {
            patch.enable();
        }
    }

    fn library_loaded(&mut self, library: platform::LibraryHandle) {
        let state = &mut *self.state;
        for group in &mut state.patch_groups {
            if !group.library_loaded {
                if let Some(ref name) = group.library {
                    if platform::lib_handle_equals_name(library, name) {
                        for func in &group.init_funcs {
                            unsafe { func(library as usize, &mut state.exec_heap) }
                        }
                        for key in &group.patches {
                            if let Some(patch) = state.patches.get_mut(key) {
                                unsafe { patch.library_loaded(library, &mut state.exec_heap); }
                            }
                        }
                        group.library_loaded = true;
                    }
                }
            }
        }
        for patch in state.all_module_patches.iter_mut() {
            patch.apply_new(library, &mut state.exec_heap);
        }
    }

    fn library_unloaded(&mut self, library: platform::LibraryHandle) {
        let state = &mut *self.state;
        for group in &mut state.patch_groups {
            if group.library_loaded {
                if let Some(ref name) = group.library {
                    if platform::lib_handle_equals_name(library, name) {
                        for key in &group.patches {
                            if let Some(patch) = state.patches.get_mut(key) {
                                patch.library_unloaded(&mut state.exec_heap);
                            }
                        }
                        group.library_loaded = false;
                    }
                }
            }
        }
        for patch in state.all_module_patches.iter_mut() {
            patch.library_unloaded(library, &mut state.exec_heap);
        }
    }

    fn apply_system_patches(&mut self) {
        if self.state.sys_patch_count == 0 {
           self.state.sys_patch_count += 1;
           let mut patcher = self.patch_all_modules();
           platform::apply_library_loading_hook(self.parent, &mut patcher);
           patcher.apply();
        } else {
            self.state.sys_patch_count += 1;
        }
    }
}

impl<'a: 'b, 'b> ModulePatcher<'a, 'b> {
    /// Creates a hook from `hook` to closure `target`.
    ///
    /// `target`'s signature has to be otherwise equivalent to what was specified in `hook`,
    /// but it has an additional paremeter `&Fn()` that can be used to call the original
    /// function.
    ///
    /// For example, if the hook is specified for `fn something(i32, *const u32) -> u32`,
    /// `target` has to be
    /// `fn target(first: i32, second: *const u32, orig: &Fn(i32, *const u32) -> u32) -> u32`.
    /// If using the closure syntax, Rust cannot infer type for the original function, so it must
    /// be specified as `|first, second, orig: &Fn(_, _) -> _|`.
    pub unsafe fn hook_closure<H, T>(&mut self, _hook: H, target: T) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, true)
    }

    /// Creates a hook from `hook` to closure `target`.
    ///
    /// `target`'s signature has to be otherwise equivalent to what was specified in `hook`,
    /// but it has an additional paremeter `&Fn()` that can be used to call the original
    /// function.
    ///
    /// For example, if the hook is specified for `fn something(i32, *const u32) -> u32`,
    /// `target` has to be
    /// `fn target(first: i32, second: *const u32, orig: &Fn(i32, *const u32) -> u32) -> u32`.
    /// If using the closure syntax, Rust cannot infer type for the original function, so it must
    /// be specified as `|first, second, orig: &Fn(_, _) -> _|`.
    pub unsafe fn call_hook_closure<H, T>(&mut self, _hook: H, target: T) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, false)
    }

    fn add_hook<H, T>(&mut self, target: T, replacing: bool) -> Patch
    where H: AddressHookClosure<T> {
        let target = H::write_target_objects(target);
        let patch = ModulePatch {
            variant: ModulePatchType::Hook(HookPatch {
                wrapper_code: H::wrapper_assembler(target.as_ptr()),
                wrapper_target: target,
                wrapper: None,
                orig_ins_len: 0,
                replacing: replacing,
            }),
            library: self.library.clone(),
            address: H::address(),
            enabled: false,
            active: false,
        };
        let key = self.parent.state.patches.alloc_slot();
        self.patches.push((patch, key.clone()));
        Patch(PatchEnum::Regular(key))
    }

    /// Creates a hook from `hook` to closure `target`.
    ///
    /// The original function will not be called afterwards. To apply a non-modifying hook, use
    /// `hook_closure()`, `call_hook()` or `hook_opt()`.
    pub unsafe fn hook<H>(&mut self, _hook: H, target: H::Fnptr) -> Patch
    where H: AddressHook,
    {
        _hook.hook(self, target)
    }

    /// Applies a hook to a function, with possibility to call the original function during hook.
    ///
    /// Effectively equivalent to `hook_closure()`, but `target` is an `unsafe fn` instead
    /// of a safe closure.
    pub unsafe fn hook_opt<H>(&mut self, _hook: H, target: H::OptFnptr) -> Patch
    where H: AddressHook,
    {
        _hook.hook_opt(self, target)
    }

    /// Applies and enables the patches which have been created using this `ModulePatcher`.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply(mut self) -> Patch {
        self.parent.apply_system_patches();
        // Have to do this as actually consuming is not allowed due to Drop impl
        let patches = mem::replace(&mut self.patches, vec![]);
        let init_fns = mem::replace(&mut self.init_fns, vec![]);
        let library = mem::replace(&mut self.library, None);
        ModulePatcher::apply_patches(self.parent, patches, init_fns, library, false)
    }

    /// Applies the patches which have been created using this `ModulePatcher`, without
    /// enabling them.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply_disabled(mut self) -> Patch {
        self.parent.apply_system_patches();
        let patches = mem::replace(&mut self.patches, vec![]);
        let init_fns = mem::replace(&mut self.init_fns, vec![]);
        let library = mem::replace(&mut self.library, None);
        ModulePatcher::apply_patches(self.parent, patches, init_fns, library, false)
    }

    fn apply_patches(parent: &mut ActivePatcher,
                     mut patches: Vec<(ModulePatch, patch_map::Key)>,
                     init_fns: Vec<InitFn>,
                     library: Option<Arc<platform::LibraryName>>,
                     enable: bool
                    ) -> Patch
    {
        let handle = library_name_to_handle_opt(&library);
        if let Some(handle) = handle {
            for func in &init_fns {
                unsafe { func(handle as usize, &mut parent.state.exec_heap); }
            }
        }

        if enable {
            if let Some(handle) = handle {
                let _protection = platform::MemoryProtection::new(handle);
                for &mut (ref mut patch, _) in &mut patches {
                    unsafe { patch.enable(handle, &mut parent.state.exec_heap); }
                }
            } else {
                for &mut (ref mut patch, _) in &mut patches {
                    patch.mark_enabled();
                }
            }
        }
        let group = patches.iter()
            .map(|&(_, ref key)| PatchEnum::Regular(key.clone()))
            .collect();
        let keys = patches.iter()
            .map(|&(_, ref key)| key.clone())
            .collect();

        for (patch, key) in patches {
            parent.state.patches.assign(key, patch);
        }

        parent.state.patch_groups.push(PatchGroup {
            library: library,
            patches: keys,
            init_funcs: init_fns,
            library_loaded: handle.is_some(),
        });
        Patch(PatchEnum::Group(group))
    }

    /// Calls this function whenever the process loads module that is being currently patched.
    /// If the module is currently loaded, the function gets called during `apply()` and
    /// equivalent functions.
    ///
    /// Mainly meant for `whack_vars!` and `whack_funcs!` macros, as the addition cannot be
    /// reverted.
    #[doc(hidden)]
    pub unsafe fn add_init_fn(&mut self, func: InitFn) {
        self.init_fns.push(func);
    }

    /// Writes `val` into `address`.
    ///
    /// Generally you'd use integer values, if there are other `repr(C)` types that can be safely
    /// copied to memory, they can be used as well.
    pub unsafe fn replace_val<T: Copy>(&mut self, address: usize, val: T) -> Patch {
        use std::{mem, slice};
        let slice = slice::from_raw_parts(&val as *const T as *const u8, mem::size_of::<T>());
        self.replace(address, slice)
    }

    /// Replaces `length` bytes starting from `address` with nop instructions.
    pub unsafe fn nop(&mut self, address: usize, length: usize) -> Patch {
        use std::iter::repeat;
        let nops: SmallVec<[u8; 16]> = repeat(platform::nop()).take(length).collect();
        self.replace(address, &nops)
    }

    /// Writes bytes from `mem` into `address`.
    pub unsafe fn replace(&mut self, address: usize, mem: &[u8]) -> Patch {
        let patch = ModulePatch {
            variant: {
                let backup_buf = std::iter::repeat(0).take(mem.len()).collect();
                ModulePatchType::Data(mem.iter().cloned().collect(), backup_buf)
            },
            library: self.library.clone(),
            address: address - self.excepted_base,
            enabled: false,
            active: false,
        };
        let key = self.parent.state.patches.alloc_slot();
        self.patches.push((patch, key.clone()));
        Patch(PatchEnum::Regular(key))
    }
}

impl<'a: 'b, 'b> Drop for ModulePatcher<'a, 'b> {
    fn drop(&mut self) {
        // Apply patches if they weren't applied
        if !self.patches.is_empty() {
            self.parent.apply_system_patches();
            let patches = mem::replace(&mut self.patches, vec![]);
            let library = mem::replace(&mut self.library, None);
            let init_fns = mem::replace(&mut self.init_fns, vec![]);
            ModulePatcher::apply_patches(self.parent, patches, init_fns, library, true);
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

    /// Applies and enables the patches which have been created using this `AllModulesPatcher`.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply(mut self) -> Patch {
        self.parent.apply_system_patches();
        // Have to do this as actually consuming is not allowed due to Drop impl
        let patches = mem::replace(&mut self.patches, vec![]);
        AllModulesPatcher::apply_patches(self.parent, patches, true)
    }

    /// Applies the patches which have been created using this `AllModulesPatcher`, without
    /// enabling them.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply_disabled(mut self) -> Patch {
        self.parent.apply_system_patches();
        let patches = mem::replace(&mut self.patches, vec![]);
        AllModulesPatcher::apply_patches(self.parent, patches, false)
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
            self.parent.apply_system_patches();
            let patches = mem::replace(&mut self.patches, vec![]);
            AllModulesPatcher::apply_patches(self.parent, patches, true);
        }
    }
}

/// An exported function, identified either by its name or ordinal.
pub enum Export<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
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
