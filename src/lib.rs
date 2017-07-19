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

use smallvec::SmallVec;

use patch_map::PatchMap;

struct ImportHook {
    library: Cow<'static, [u8]>,
    export: Export<'static>,
    wrapper_code: ::platform::HookWrapCode,
    // This keeps the hook target alive as long as the hook exists.
    #[allow(dead_code)]
    wrapper_target: Box<[u8]>,
}

enum ModulePatchType {
    Hook(HookPatch),
    Data(ReplacingPatch),
    Import(ImportHook, *const u8, *const u8),
}

unsafe impl Send for ModulePatchType {
}

struct ReplacingPatch {
    data: SmallVec<[u8; 16]>,
    backup_buf: SmallVec<[u8; 16]>,
    // Relative from base address
    address: usize,
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
    // Relative from base address
    address: usize,
}

struct ModulePatch {
    variant: ModulePatchType,
    library: Option<Arc<platform::LibraryName>>,
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

#[doc(hidden)]
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
    Group(patch_map::Key),
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
    unsafe fn enable(&mut self,
                     handle: platform::LibraryHandle,
                     heap: &mut platform::ExecutableHeap) {
        if self.active {
            self.disable(Some(handle), heap);
        }
        match self.variant {
            ModulePatchType::Hook(ref mut hook) => {
                let address = (handle as usize + hook.address) as *const u8;
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
            ModulePatchType::Data(ref mut patch) => {
                let address = (handle as usize + patch.address) as *const u8;
                let len = patch.data.len();
                ptr::copy_nonoverlapping(address, patch.backup_buf.as_mut_ptr(), len);
                ptr::copy_nonoverlapping(patch.data.as_ptr(), address as *mut u8, len);
            }
            ModulePatchType::Import(ref hook, ref mut stored_wrapper, ref mut orig) => {
                let addr = platform::import_addr(handle, &hook.library, &hook.export);
                if let Some(addr) = addr {
                    *orig  = *addr as *const u8;
                    let out_ptr = Some(*orig as *const u8);
                    let (wrapper, _) = hook.wrapper_code.write_wrapper(None, heap, out_ptr);
                    *stored_wrapper = wrapper;
                    *addr = wrapper as usize;
                }
            }
        }
        self.active = true;
    }

    unsafe fn disable(&mut self,
                      handle: Option<platform::LibraryHandle>,
                      heap: &mut platform::ExecutableHeap) {
        if self.active {
            if let Some(handle) = handle {
                match self.variant {
                    ModulePatchType::Hook(ref mut hook) => {
                        let address = (handle as usize + hook.address) as *mut u8;
                        hook.revert(address, heap);
                    }
                    ModulePatchType::Data(ReplacingPatch { ref backup_buf, address, .. }) => {
                        let address = (handle as usize + address) as *mut u8;
                        ptr::copy_nonoverlapping(backup_buf.as_ptr(), address, backup_buf.len());
                    }
                    ModulePatchType::Import(ref hook, wrapper, ref orig) => {
                        let addr = platform::import_addr(handle, &hook.library, &hook.export);
                        if let Some(addr) = addr {
                            *addr = *orig as usize;
                            heap.free(wrapper as *mut u8);
                        }
                    }
                }
            } else {
                match self.variant {
                    ModulePatchType::Hook(ref mut hook) => hook.free_wrapper(heap),
                    ModulePatchType::Data(_) => (),
                    ModulePatchType::Import(_, wrapper, _) => heap.free(wrapper as *mut u8),
                }
            }
            self.active = false;
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
    mutex: Mutex<PatcherState>,
}

/// Allows actually patching the current process.
///
/// Accessible with `Patcher.patch()`, see `Patcher` for more information.
#[must_use]
pub struct ActivePatcher<'a> {
    state: MutexGuard<'a, PatcherState>,
}

struct PatcherState {
    patches: PatchMap<ModulePatch>,
    patch_groups: PatchMap<PatchGroup>,
    exec_heap: platform::ExecutableHeap,
}

/// Groups of patches that apply to a single module.
struct PatchGroup {
    library: Option<Arc<platform::LibraryName>>,
    patches: Vec<patch_map::Key>,
    init_funcs: Vec<InitFn>,
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
            mutex: Mutex::new(PatcherState::new()),
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
            state: guard
        })
    }
}

impl PatcherState {
    fn new() -> PatcherState {
        PatcherState {
            patches: PatchMap::new(),
            patch_groups: PatchMap::new(),
            exec_heap: platform::ExecutableHeap::new(),
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
    /// whack_hooks!(0,
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
    pub fn custom_calling_convention<H>(&mut self, _hook: H, target: H::Fnptr) -> *const u8
    where H: AddressHook,
    {
        unsafe { _hook.custom_calling_convention(target, &mut self.state.exec_heap) }
    }

    /// Disables a patch which has been created with this `Patcher`.
    pub unsafe fn disable_patch(&mut self, patch: &Patch) {
        let mut memprotect_guard = SmallVec::new();
        self.unprotect_patch_memory(&patch.0, &mut memprotect_guard);
        self.disable_patch_internal(&patch.0)
    }

    unsafe fn disable_patch_internal(&mut self, patch: &PatchEnum) {
        let state = &mut *self.state;
        match *patch {
            PatchEnum::Regular(ref key) => {
                if let Some(patch) = state.patches.get_mut(key) {
                    let handle = library_name_to_handle_opt(&patch.library);
                    patch.disable(handle, &mut state.exec_heap);
                }
            }
            PatchEnum::Group(ref key) => {
                if let Some(group) = state.patch_groups.get_mut(key) {
                    let handle = library_name_to_handle_opt(&group.library);
                    for key in &group.patches {
                        if let Some(patch) = state.patches.get_mut(key) {
                            patch.disable(handle, &mut state.exec_heap);
                        }
                    }
                }
            }
        }
    }

    /// (Re-)Enables a patch which has been created with this `Patcher`.
    ///
    /// If the patch modifies a dll that gets loaded after the the patch was created,
    /// this function has to be called to actually patch the dll.
    pub unsafe fn enable_patch(&mut self, patch: &Patch) {
        let mut memprotect_guard = SmallVec::new();
        self.unprotect_patch_memory(&patch.0, &mut memprotect_guard);
        self.enable_patch_internal(&patch.0)
    }

    unsafe fn enable_patch_internal(&mut self, patch: &PatchEnum) {
        let state = &mut *self.state;
        match *patch {
            PatchEnum::Regular(ref key) => {
                if let Some(patch) = state.patches.get_mut(key) {
                    if let Some(handle) = library_name_to_handle_opt(&patch.library) {
                        patch.enable(handle, &mut state.exec_heap);
                    }
                }
            }
            PatchEnum::Group(ref key) => {
                if let Some(group) = state.patch_groups.get_mut(key) {
                    if let Some(handle) = library_name_to_handle_opt(&group.library) {
                        for func in &group.init_funcs {
                            func(handle as usize, &mut state.exec_heap);
                        }
                        for key in &group.patches {
                            if let Some(patch) = state.patches.get_mut(key) {
                                patch.enable(handle, &mut state.exec_heap);
                            }
                        }
                    }
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
            PatchEnum::Group(ref key) => {
                if let Some(handle) = self.state.patch_groups.get(key)
                    .and_then(|p| library_name_to_handle_opt(&p.library)) {
                    add_handle_if_needed(protections, handle);
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
        for group in state.patch_groups.iter() {
            if let Some(handle) = library_name_to_handle_opt(&group.library) {
                if !protections.iter().any(|&(x, _)| x == handle) {
                    let protection = platform::MemoryProtection::new(handle);
                    protections.push((handle, protection));
                }
            }
        }
        protections
    }

    /// Disables all patches.
    pub unsafe fn unpatch(&mut self) {
        let _protections = self.unprotect_all_patch_memory();
        let state = &mut *self.state;
        for group in state.patch_groups.iter_mut() {
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
    }

    /// Enables every patch that has been associated with this `Patcher`.
    pub unsafe fn repatch(&mut self) {
        let _protections = self.unprotect_all_patch_memory();
        let state = &mut *self.state;
        for group in state.patch_groups.iter_mut() {
            if let Some(handle) = library_name_to_handle_opt(&group.library) {
                for func in &group.init_funcs {
                    func(handle as usize, &mut state.exec_heap);
                }
                for key in &group.patches {
                    if let Some(patch) = state.patches.get_mut(key) {
                        patch.enable(handle, &mut state.exec_heap);
                    }
                }
            }
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
        self.add_hook::<H, T>(target, true, H::address())
    }

    /// Creates a hook to any address, insted of the usual case where the address is
    /// specified during hook declaration.
    ///
    /// Address is relative to the module base.
    pub unsafe fn hook_closure_address<H, T>(&mut self, _hook: H, target: T, address: usize) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, true, address)
    }

    // Not shown since calling `orig` is actually not allowed.
    #[doc(hidden)]
    pub unsafe fn call_hook_closure<H, T>(&mut self, _hook: H, target: T) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, false, H::address())
    }

    fn add_hook<H, T>(&mut self, target: T, replacing: bool, address: usize) -> Patch
    where H: AddressHookClosure<T> {
        let target = H::write_target_objects(target);
        let assembler = H::wrapper_assembler(target.as_ptr());
        self.add_hook_nongeneric(target, assembler, replacing, address)
    }

    // Code size optimization
    fn add_hook_nongeneric(
        &mut self,
        target: Box<[u8]>,
        wrapper_assembler: platform::HookWrapAssembler,
        replacing: bool,
        address: usize,
    ) -> Patch {
        let patch = ModulePatch {
            variant: ModulePatchType::Hook(HookPatch {
                wrapper_code: wrapper_assembler,
                wrapper_target: target,
                wrapper: None,
                orig_ins_len: 0,
                replacing: replacing,
                address: address,
            }),
            library: self.library.clone(),
            active: false,
        };
        let key = self.parent.state.patches.alloc_slot();
        self.patches.push((patch, key.clone()));
        Patch(PatchEnum::Regular(key))
    }

    /// Creates a hook from `hook` to `target`.
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

    /// Creates a non-replacing hook.
    ///
    /// Unlike other hooks, this can be safely applied in middle of a function to inspect
    /// its current state.
    pub unsafe fn call_hook<H>(&mut self, _hook: H, target: H::Fnptr) -> Patch
    where H: AddressHook,
    {
        _hook.call_hook(self, target)
    }

    /// Applies and enables the patches which have been created using this `ModulePatcher`.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply(mut self) -> Patch {
        // Have to do this as actually consuming is not allowed due to Drop impl
        let patches = mem::replace(&mut self.patches, vec![]);
        let init_fns = mem::replace(&mut self.init_fns, vec![]);
        let library = mem::replace(&mut self.library, None);
        ModulePatcher::apply_patches(self.parent, patches, init_fns, library, true)
    }

    /// Applies the patches which have been created using this `ModulePatcher`, without
    /// enabling them.
    ///
    /// Returns a `Patch` which can be used to control all applied patches at once.
    pub fn apply_disabled(mut self) -> Patch {
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
            }
        }
        let keys = patches.iter()
            .map(|&(_, ref key)| key.clone())
            .collect();

        for (patch, key) in patches {
            parent.state.patches.assign(key, patch);
        }

        let group_key = parent.state.patch_groups.insert(PatchGroup {
            library: library,
            patches: keys,
            init_funcs: init_fns,
        });
        Patch(PatchEnum::Group(group_key))
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
            variant: ModulePatchType::Data(ReplacingPatch {
                data: mem.iter().cloned().collect(),
                backup_buf: std::iter::repeat(0).take(mem.len()).collect(),
                address: address - self.excepted_base,
            }),
            library: self.library.clone(),
            active: false,
        };
        let key = self.parent.state.patches.alloc_slot();
        self.patches.push((patch, key.clone()));
        Patch(PatchEnum::Regular(key))
    }

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
        let patch = ModulePatch {
            variant: ModulePatchType::Import(ImportHook {
                library: library,
                export: H::default_export(),
                wrapper_code: H::wrapper_assembler(wrapper_target.as_ptr())
                    .generate_wrapper_code(OrigFuncCallback::ImportHook),
                wrapper_target: wrapper_target,
            }, ptr::null(), ptr::null()),
            library: self.library.clone(),
            active: false,
        };
        let key = self.parent.state.patches.alloc_slot();
        self.patches.push((patch, key.clone()));
        Patch(PatchEnum::Regular(key))
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
}

impl<'a: 'b, 'b> Drop for ModulePatcher<'a, 'b> {
    /// Applies patches with `apply()` if they weren't explicitly applied.
    fn drop(&mut self) {
        if !self.patches.is_empty() || !self.init_fns.is_empty() {
            let patches = mem::replace(&mut self.patches, vec![]);
            let library = mem::replace(&mut self.library, None);
            let init_fns = mem::replace(&mut self.init_fns, vec![]);
            ModulePatcher::apply_patches(self.parent, patches, init_fns, library, true);
        }
    }
}

/// An exported function, identified either by its name or ordinal.
#[doc(hidden)]
pub enum Export<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
}

/// Redirects stderr to a file.
pub unsafe fn redirect_stderr<F: AsRef<Path>>(filename: F) -> bool {
    platform::redirect_stderr(filename.as_ref())
}

/// Created with `whack_vars!` macrow.
#[doc(hidden)]
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
    #[inline]
    fn deref<'a>(&'a self) -> &'a T {
        unsafe { mem::transmute(self.address) }
    }
}

impl<T> ops::DerefMut for Variable<T> {
    #[inline]
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
