extern crate byteorder;
extern crate lde;
extern crate smallvec;
extern crate winapi;

#[macro_use]
#[doc(hidden)]
pub mod macros;
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

mod helpers;
mod insertion_sort;
mod patch_map;

type InitFn = unsafe fn(usize, &mut platform::ExecutableHeap);

pub use macros::{
    AddressHook, AddressHookClosure, ExportHook, ExportHookClosure, HookDecl, HookDeclClosure
};

use std::{mem, ops, ptr};
use std::borrow::Cow;
use std::ffi::OsStr;
use std::marker::{PhantomData, Sync};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::os::raw::c_void;

use smallvec::SmallVec;

use patch_map::PatchMap;

struct ImportHook {
    library: Cow<'static, [u8]>,
    export: Export<'static>,
    wrapper_code: ::platform::HookWrapCode,
    // This keeps the hook target alive as long as the hook exists.
    #[allow(dead_code)]
    wrapper_target: Box<[u8]>,
    stored_wrapper: *const u8,
    orig: *const u8,
}

enum ModulePatchType {
    Hook(Box<HookPatch>),
    Data(ReplacingPatch),
    Import(Box<ImportHook>),
}

unsafe impl Send for ModulePatchType {
}

struct ReplacingPatch {
    data: SmallVec<[u8; 16]>,
    backup_buf: SmallVec<[u8; 16]>,
    // Relative from base address
    address: usize,
}

#[doc(hidden)]
pub struct GeneratedHook {
    pub wrapper: *const u8,
    orig_ins: *const u8,
    orig_ins_len: usize,
    pointer_to_wrapper: *const *const u8,
}

struct HookPatch {
    wrapper_code: platform::HookWrapAssembler,
    // This keeps the hook target alive as long as the hook exists.
    #[allow(dead_code)]
    wrapper_target: Box<[u8]>,
    entry: Option<GeneratedHook>,
    // For inline hooks.
    exit: Option<GeneratedHook>,
    inline_parent_entry: Option<GeneratedHook>,
    // Is this a replacing hook or just a detour
    ty: HookType,
}

struct ModulePatch {
    variant: ModulePatchType,
    image_base: ImageBase,
    // Is the patch is actually applied to a module (hooks have allocated their wrapper code)
    active: bool,
}

#[derive(Clone, Eq, PartialEq)]
enum ImageBase {
    Executable,
    Library(Arc<platform::LibraryName>),
    // Allows separate addresses for writing and out wrapper targets
    Memory { write: *mut c_void, exec: *mut c_void },
}

unsafe impl Send for ImageBase {}
unsafe impl Sync for ImageBase {}

fn image_base_to_handles_opt(val: &ImageBase) -> Option<PatchEnableHandles> {
    match *val {
        ImageBase::Executable => Some(PatchEnableHandles::same(platform::exe_handle())),
        ImageBase::Library(ref s) => {
            platform::library_name_to_handle(s).map(|x| PatchEnableHandles::same(x))
        }
        ImageBase::Memory { exec, write } => Some(PatchEnableHandles {
            exec: exec as platform::LibraryHandle,
            write: write as platform::LibraryHandle,
        }),
    }
}

/// For supporting different exec-read/write addresses
struct PatchEnableHandles {
    exec: platform::LibraryHandle,
    write: platform::LibraryHandle,
}

impl PatchEnableHandles {
    fn same(handle: platform::LibraryHandle) -> PatchEnableHandles {
        PatchEnableHandles {
            exec: handle,
            write: handle,
        }
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
    // Inline hook, technically superset of Overwritten and Hook, but has a TLS cost.
    // (entry, exit, uninlined_func_entry)
    Inline(*const u8, *const u8, *const u8),
    // For import hooks, allows setting the value once the library is actually loaded.
    ImportHook,
}

// All addresses are relative
enum HookType {
    // Allows hooking at function entry and calling it afterwards.
    // Grouped with OrigFuncCallback::OverWritten and ModulePatcher::hook.
    Entry(usize),
    // Allows hooking at any point without disrupting the function state
    // Grouped with OrigFuncCallback::Hook and ModulePatcher::call_hook.
    InlineNoOrig(usize),
    // Allows hooking at any point without disrupting the function state,
    // and calling the original function, but uses TLS to track recursion.
    // Grouped with OrigFuncCallback::Inline and ModulePatcher::inline_hook.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    Inline(usize, usize, usize),
}


pub use platform::Location as Arg;

/// Defines entry, exit, and argument locations for inline hooking (`ModulePatcher::inline_hook`).
pub struct InlineHook {
    pub entry: usize,
    pub exit: usize,
    /// The entry to the function which contains the inlined function.
    /// Can be left 0, but may cause issues if the hooked function recurses.
    pub inline_parent_entry: usize,
    /// Registers/stack locations of the arguments, ordered to match hook declaration.
    /// Having two arguments equal to each other is not allowed.
    pub args: Vec<Arg>,
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

impl GeneratedHook {
    unsafe fn revert(&self, address: *mut u8) {
        std::ptr::copy_nonoverlapping(self.orig_ins, address, self.orig_ins_len);
    }
}

impl ModulePatch {
    unsafe fn enable(
        &mut self,
        handles: &PatchEnableHandles,
        heap: &mut platform::ExecutableHeap
    ) {
        if self.active {
            self.disable(Some(handles.write));
        }
        match self.variant {
            ModulePatchType::Hook(ref mut hook) => {
                if let HookType::Inline(..) = hook.ty {
                    hook.apply_inline(handles, heap)
                } else {
                    hook.apply_no_inline(handles, heap)
                }
            }
            ModulePatchType::Data(ref mut patch) => {
                patch.apply(handles);
            }
            ModulePatchType::Import(ref mut hook) => {
                hook.apply(handles, heap);
            }
        }
        self.active = true;
    }

    unsafe fn disable(&mut self, handle: Option<platform::LibraryHandle>) {
        if self.active {
            if let Some(handle) = handle {
                match self.variant {
                    ModulePatchType::Hook(ref mut hook) => {
                        let (entry, exit, parent) = match hook.ty {
                            HookType::Entry(a) | HookType::InlineNoOrig(a) => (a, !0, !0),
                            HookType::Inline(a, e, p) => (a, e, p),
                        };
                        if let Some(ref e) = hook.entry {
                            e.revert((handle as usize + entry) as *mut u8);
                        }
                        if let Some(ref e) = hook.exit {
                            e.revert((handle as usize + exit) as *mut u8);
                        }
                        if let Some(ref e) = hook.inline_parent_entry {
                            e.revert((handle as usize + parent) as *mut u8);
                        }
                    }
                    ModulePatchType::Data(ReplacingPatch { ref backup_buf, address, .. }) => {
                        let address = (handle as usize + address) as *mut u8;
                        ptr::copy_nonoverlapping(backup_buf.as_ptr(), address, backup_buf.len());
                    }
                    ModulePatchType::Import(ref mut hook) => {
                        let addr = platform::import_addr(handle, &hook.library, &hook.export);
                        if let Some(addr) = addr {
                            *addr = hook.orig as usize;
                        }
                    }
                }
            }
            self.active = false;
        }
    }
}

impl HookPatch {
    /// Applies an non-inline hook.
    pub unsafe fn apply_no_inline(
        &mut self,
        handles: &PatchEnableHandles,
        heap: &mut platform::ExecutableHeap,
    ) {
        let base = handles.exec as usize;
        let to_abs = |relative: usize| (base + relative) as *const u8;
        let entry = match self.ty {
            HookType::Entry(a) | HookType::InlineNoOrig(a) => a,
            HookType::Inline(..) => return,
        };
        if self.entry.is_none() {
            let orig = match self.ty {
                HookType::Entry(a) => OrigFuncCallback::Overwritten(to_abs(a)),
                HookType::InlineNoOrig(a) => OrigFuncCallback::Hook(to_abs(a)),
                HookType::Inline(..) => return,
            };
            let code = self.wrapper_code.generate_wrapper_code(orig);
            let (entry, _, _) = code.write_wrapper(
                Some(to_abs(entry)),
                None,
                None,
                heap,
                None,
            );
            self.entry = Some(entry);
        }
        if let Some(ref hook) = self.entry {
            let write_address = (handles.write as usize + entry) as *mut u8;
            platform::write_jump_to_ptr(write_address, hook.pointer_to_wrapper);
        }
    }

    /// Applies an inline hook.
    pub unsafe fn apply_inline(
        &mut self,
        handles: &PatchEnableHandles,
        heap: &mut platform::ExecutableHeap,
    ) {
        let base = handles.exec as usize;
        let to_abs = |relative: usize| (base + relative) as *const u8;
        let (entry, exit, inline_parent_entry) = match self.ty {
            HookType::Inline(entry, exit, parent) => (entry, exit, parent),
            _ => return,
        };
        if self.entry.is_none() {
            let (a, b, c) = match self.ty {
                HookType::Inline(a, e, p) => (to_abs(a), to_abs(e), to_abs(p)),
                _ => return,
            };
            let code = self.wrapper_code.generate_wrapper_code_inline(a, b, c);
            let (entry, exit, parent) = code.write_wrapper(
                Some(to_abs(entry)),
                Some(to_abs(exit)),
                match inline_parent_entry != 0 {
                    true => Some(to_abs(inline_parent_entry)),
                    false => None,
                },
                heap,
                None,
            );
            self.entry = Some(entry);
            self.exit = exit;
            self.inline_parent_entry = parent;
        }
        if let Some(ref hook) = self.entry {
            let write_address = (handles.write as usize + entry) as *mut u8;
            platform::write_jump_to_ptr(write_address, hook.pointer_to_wrapper);
        }
        if let Some(ref hook) = self.exit {
            let write_address = (handles.write as usize + exit) as *mut u8;
            platform::write_jump_to_ptr(write_address, hook.pointer_to_wrapper);
        }
        if let Some(ref hook) = self.inline_parent_entry {
            let write_address = (handles.write as usize + inline_parent_entry) as *mut u8;
            platform::write_jump_to_ptr(write_address, hook.pointer_to_wrapper);
        }
    }
}

impl ReplacingPatch {
    pub unsafe fn apply(&mut self, handles: &PatchEnableHandles) {
        let address = (handles.write as usize + self.address) as *const u8;
        let len = self.data.len();
        ptr::copy_nonoverlapping(address, self.backup_buf.as_mut_ptr(), len);
        ptr::copy_nonoverlapping(self.data.as_ptr(), address as *mut u8, len);
    }
}

impl ImportHook {
    pub unsafe fn apply(
        &mut self,
        handles: &PatchEnableHandles,
        heap: &mut platform::ExecutableHeap,
    ) {
        let addr = platform::import_addr(handles.write, &self.library, &self.export);
        if let Some(addr) = addr {
            if self.stored_wrapper.is_null() {
                let out_ptr = Some(*addr as *const u8);
                let (entry, _, _) =
                    self.wrapper_code.write_wrapper(None, None, None, heap, out_ptr);
                self.stored_wrapper = entry.wrapper;
            }
            self.orig = *addr as *const u8;
            *addr = self.stored_wrapper as usize;
        }
    }
}

/// The main patching structure.
///
/// Keeps track of applied patches and provides a heap which the patches
/// will use to allocate executable memory as needed.
///
/// Usually this would be wrapped in a static mutex to keep patches alive
/// for the entirety of process's runtime.
pub struct Patcher {
    patches: PatchMap<ModulePatch>,
    patch_groups: PatchMap<PatchGroup>,
    exec_heap: platform::ExecutableHeap,
}

/// Groups of patches that apply to a single module.
struct PatchGroup {
    image_base: ImageBase,
    patches: Vec<patch_map::Key>,
    /// These are stored here so that reapplying patches after a dll is
    /// loaded won't require anything more than `Patcher::enable_patch`.
    /// Could possibly require user to re-call init funcs though.
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
pub struct ModulePatcher<'b> {
    parent: &'b mut Patcher,
    patches: Vec<patch_map::Key>,
    image_base: ImageBase,
    init_fns: Vec<InitFn>,
    expected_base: usize,
    patch_enable_handles: Option<PatchEnableHandles>,
    /// RAII guard, if the module is loaded (and not memory)
    #[allow(dead_code)]
    protection: Option<platform::MemoryProtection>,
}

impl Patcher {
    /// Creates a new `Patcher`.
    pub fn new() -> Patcher {
        Patcher {
            patches: PatchMap::new(),
            patch_groups: PatchMap::new(),
            exec_heap: platform::ExecutableHeap::new(),
        }
    }

    /// Begins patching the executable.
    ///
    /// Call methods of the returned `ModulePatcher` to apply hooks.
    /// Applying constant/nop patches requires specifying `expected_base`, otherwise it can
    /// be 0.
    pub fn patch_exe<'b>(&'b mut self, expected_base: usize) -> ModulePatcher<'b> {
        let image_base = ImageBase::Executable;
        let patch_enable_handles = image_base_to_handles_opt(&image_base);
        let protection = patch_enable_handles.as_ref()
            .map(|handles| platform::MemoryProtection::new(handles.write));
        ModulePatcher {
            parent: self,
            patches: Vec::new(),
            init_fns: Vec::new(),
            image_base,
            expected_base,
            patch_enable_handles,
            protection,
        }
    }

    /// Begins patching a library
    ///
    /// Call methods of the returned `ModulePatcher` to apply hooks.
    /// Applying constant/nop patches requires specifying `expected_base`, otherwise it can
    /// be 0.
    pub fn patch_library<'b, T>(
        &'b mut self,
        library: T,
        expected_base: usize,
    ) -> ModulePatcher<'b>
    where T: AsRef<OsStr>
    {
        let image_base = ImageBase::Library(Arc::new(platform::library_name(library)));
        let patch_enable_handles = image_base_to_handles_opt(&image_base);
        let protection = patch_enable_handles.as_ref()
            .map(|handles| platform::MemoryProtection::new(handles.write));
        ModulePatcher {
            parent: self,
            patches: Vec::new(),
            init_fns: Vec::new(),
            image_base,
            expected_base,
            patch_enable_handles,
            protection,
        }
    }

    /// Begins patching arbitrary memory location as if it were a module.
    ///
    /// It is possible to use different addresses that are backed by same memory if other
    /// should be writable and other executable.
    ///
    /// Unlike with `patch_exe` and `patch_library` memory is no unprotected automatically,
    /// the caller is responsible for taking care of the memory being writable.
    ///
    /// Call methods of the returned `ModulePatcher` to apply hooks.
    /// Applying constant/nop patches requires specifying `expected_base`, otherwise it can
    /// be 0.
    pub fn patch_memory<'b>(
        &'b mut self,
        write: *mut c_void,
        execute: *mut c_void,
        expected_base: usize
    ) -> ModulePatcher<'b> {
        let image_base = ImageBase::Memory { write, exec: execute };
        let patch_enable_handles = image_base_to_handles_opt(&image_base);
        ModulePatcher {
            parent: self,
            patches: Vec::new(),
            init_fns: Vec::new(),
            image_base,
            expected_base,
            patch_enable_handles,
            protection: None,
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
    ///
    /// use std::os::raw::c_void;
    /// use std::sync::Mutex;
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
    /// thread_local!(static PATCHER: Mutex<whack::Patcher> = Mutex::new(whack::Patcher::new()));
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
        unsafe { _hook.custom_calling_convention(target, &mut self.exec_heap) }
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
                if let Some(patch) = self.patches.get_mut(key) {
                    let write_handle =
                        image_base_to_handles_opt(&patch.image_base).map(|x| x.write);
                    patch.disable(write_handle);
                }
            }
            PatchEnum::Group(ref key) => {
                if let Some(group) = self.patch_groups.get_mut(key) {
                    let write_handle =
                        image_base_to_handles_opt(&group.image_base).map(|x| x.write);
                    for key in &group.patches {
                        if let Some(patch) = self.patches.get_mut(key) {
                            patch.disable(write_handle);
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
        match *patch {
            PatchEnum::Regular(ref key) => {
                if let Some(patch) = self.patches.get_mut(key) {
                    if let Some(ref handles) = image_base_to_handles_opt(&patch.image_base) {
                        patch.enable(handles, &mut self.exec_heap);
                    }
                }
            }
            PatchEnum::Group(ref key) => {
                if let Some(group) = self.patch_groups.get_mut(key) {
                    if let Some(ref handles) = image_base_to_handles_opt(&group.image_base) {
                        for func in &group.init_funcs {
                            func(handles.exec as usize, &mut self.exec_heap);
                        }
                        for key in &group.patches {
                            if let Some(patch) = self.patches.get_mut(key) {
                                patch.enable(handles, &mut self.exec_heap);
                            }
                        }
                    }
                }
            }
        }
    }

    fn unprotect_patch_memory(
        &self,
        patch: &PatchEnum,
        protections: &mut SmallVec<[(platform::LibraryHandle, platform::MemoryProtection); 16]>,
    )
    {
        let add_handle_if_needed = |
            protections: &mut SmallVec<[(
                platform::LibraryHandle,
                platform::MemoryProtection,
            ); 16]>,
            handle
        | {
            if !protections.iter().any(|&(x, _)| x == handle) {
                let protection = platform::MemoryProtection::new(handle);
                protections.push((handle, protection));
            }
        };
        match *patch {
            PatchEnum::Regular(ref key) => {
                if let Some(handles) = self.patches.get(key)
                    .and_then(|p| match p.image_base {
                        ImageBase::Memory { .. } => None,
                        _ => image_base_to_handles_opt(&p.image_base)
                    }) {
                    add_handle_if_needed(protections, handles.write);
                }
            }
            PatchEnum::Group(ref key) => {
                if let Some(handles) = self.patch_groups.get(key)
                    .and_then(|p| match p.image_base {
                        ImageBase::Memory { .. } => None,
                        _ => image_base_to_handles_opt(&p.image_base)
                    }) {
                    add_handle_if_needed(protections, handles.write);
                }
            }
        }
    }
}

impl<'b> ModulePatcher<'b> {
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
        self.add_hook::<H, T>(target, HookType::Entry(H::address()))
    }

    /// Creates a hook to any address, insted of the usual case where the address is
    /// specified during hook declaration.
    ///
    /// Address is relative to the module base.
    pub unsafe fn hook_closure_address<H, T>(&mut self, _hook: H, target: T, address: usize) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, HookType::Entry(address))
    }

    // Not shown since calling `orig` is actually not allowed.
    #[doc(hidden)]
    pub unsafe fn call_hook_closure<H, T>(&mut self, _hook: H, target: T) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, HookType::InlineNoOrig(H::address()))
    }

    /// Hooks to inspect state at `address` (relative to module base)
    ///
    /// The hook's callback has a function to call orig, but calling it is undefined.
    /// (This is somewhat hacky function to quickly add support for inspecting hooks
    /// at dynamically known address)
    pub unsafe fn call_hook_closure_address<H, T>(&mut self, _hook: H, target: T, address: usize) -> Patch
    where H: AddressHookClosure<T> {
        self.add_hook::<H, T>(target, HookType::InlineNoOrig(address))
    }

    unsafe fn add_hook<H, T>(&mut self, target: T, ty: HookType) -> Patch
    where H: AddressHookClosure<T> {
        let target = H::write_target_objects(target);
        let assembler = H::wrapper_assembler(target.as_ptr());
        match ty {
            HookType::Entry(..) | HookType::InlineNoOrig(..) => {
                self.add_noninline_hook(ty, target, assembler)
            }
            HookType::Inline(entry, exit, parent) => {
                self.add_inline_hook(entry, exit, parent, target, assembler)
            }
        }
    }

    unsafe fn add_noninline_hook(
        &mut self,
        ty: HookType,
        target: Box<[u8]>,
        wrapper_assembler: platform::HookWrapAssembler,
    ) -> Patch {
        let mut variant = Box::new(HookPatch {
            wrapper_code: wrapper_assembler,
            wrapper_target: target,
            entry: None,
            exit: None,
            inline_parent_entry: None,
            ty,
        });
        if let Some(ref handles) = self.patch_enable_handles {
            variant.apply_no_inline(handles, &mut self.parent.exec_heap);
        }
        let patch = ModulePatch {
            variant: ModulePatchType::Hook(variant),
            image_base: self.image_base.clone(),
            active: self.patch_enable_handles.is_some(),
        };
        let key = self.parent.patches.insert(patch);
        self.patches.push(key.clone());
        Patch(PatchEnum::Regular(key))
    }

    unsafe fn add_inline_hook(
        &mut self,
        entry: usize,
        exit: usize,
        parent: usize,
        target: Box<[u8]>,
        wrapper_assembler: platform::HookWrapAssembler,
    ) -> Patch {
        let mut variant = Box::new(HookPatch {
            wrapper_code: wrapper_assembler,
            wrapper_target: target,
            entry: None,
            exit: None,
            inline_parent_entry: None,
            ty: HookType::Inline(entry, exit, parent),
        });
        if let Some(ref handles) = self.patch_enable_handles {
            variant.apply_inline(handles, &mut self.parent.exec_heap);
        }
        let patch = ModulePatch {
            variant: ModulePatchType::Hook(variant),
            image_base: self.image_base.clone(),
            active: self.patch_enable_handles.is_some(),
        };
        let key = self.parent.patches.insert(patch);
        self.patches.push(key.clone());
        Patch(PatchEnum::Regular(key))
    }

    /// Creates a hook from `hook` to `target`.
    ///
    /// The original function will not be called afterwards. To apply a non-modifying hook,
    /// use `hook_closure()`, `call_hook()` or `hook_opt()`.
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

    /// Saves the patches that were applied using this `ModulePatcher`
    /// into a group that can be enabled and disabled all at once.
    pub fn save_patch_group(self) -> Patch {
        let group_key = self.parent.patch_groups.insert(PatchGroup {
            image_base: self.image_base,
            patches: self.patches,
            init_funcs: self.init_fns,
        });
        Patch(PatchEnum::Group(group_key))
    }

    /// Calls this function whenever the process loads module that is being currently patched.
    /// If the module is currently loaded, the function gets also called.
    ///
    /// Mainly meant for `whack_vars!` and `whack_funcs!` macros, as the addition cannot be
    /// reverted.
    #[doc(hidden)]
    pub unsafe fn add_init_fn(&mut self, func: InitFn) {
        if let Some(ref handles) = self.patch_enable_handles {
            func(handles.exec as usize, &mut self.parent.exec_heap);
        }

        self.init_fns.push(func);
    }

    /// Writes `val` into `address`.
    ///
    /// Generally you'd use integer values, if there are other `repr(C)` types that can be safely
    /// copied to memory, they can be used as well.
    ///
    /// `address` uses the expected base which was specified when creating this `ModulePatcher`.
    pub unsafe fn replace_val<T: Copy>(&mut self, address: usize, val: T) -> Patch {
        use std::{slice};
        let slice = slice::from_raw_parts(&val as *const T as *const u8, mem::size_of::<T>());
        self.replace(address, slice)
    }

    /// Replaces `length` bytes starting from `address` with nop instructions.
    ///
    /// `address` uses the expected base which was specified when creating this `ModulePatcher`.
    pub unsafe fn nop(&mut self, address: usize, length: usize) -> Patch {
        use std::iter::repeat;
        let nops: SmallVec<[u8; 16]> = repeat(platform::nop()).take(length).collect();
        self.replace(address, &nops)
    }

    /// Writes bytes from `mem` into `address`.
    ///
    /// `address` uses the expected base which was specified when creating this `ModulePatcher`.
    pub unsafe fn replace(&mut self, address: usize, mem: &[u8]) -> Patch {
        let mut variant = ReplacingPatch {
            data: mem.iter().cloned().collect(),
            backup_buf: std::iter::repeat(0).take(mem.len()).collect(),
            address: address - self.expected_base,
        };
        if let Some(ref handles) = self.patch_enable_handles {
            variant.apply(handles);
        }
        let patch = ModulePatch {
            variant: ModulePatchType::Data(variant),
            image_base: self.image_base.clone(),
            active: self.patch_enable_handles.is_some(),
        };
        let key = self.parent.patches.insert(patch);
        self.patches.push(key.clone());
        Patch(PatchEnum::Regular(key))
    }

    /// Creates a `Patch` which hooks a function `hook`, exported by `library` by editing every
    /// module's import table.
    ///
    /// This function doesn't require `library` to be loaded. As such, if the library doesn't
    /// actually export `hook`, any errors will not be reported.
    pub unsafe fn import_hook_closure<H, T, L>(
        &mut self,
        library: L,
        _hook: H,
        target: T,
    ) -> Patch
    where H: ExportHookClosure<T>,
          L: Into<Cow<'static, [u8]>>,
    {
        let wrapper_target = H::write_target_objects(target);
        let mut variant = Box::new(ImportHook {
            library: library.into(),
            export: H::default_export(),
            wrapper_code: H::wrapper_assembler(wrapper_target.as_ptr())
                .generate_wrapper_code(OrigFuncCallback::ImportHook),
            wrapper_target,
            orig: ptr::null(),
            stored_wrapper: ptr::null(),
        });
        if let Some(ref handles) = self.patch_enable_handles {
            variant.apply(handles, &mut self.parent.exec_heap);
        }
        let patch = ModulePatch {
            variant: ModulePatchType::Import(variant),
            image_base: self.image_base.clone(),
            active: self.patch_enable_handles.is_some(),
        };
        let key = self.parent.patches.insert(patch);
        self.patches.push(key.clone());
        Patch(PatchEnum::Regular(key))
    }

    /// Same as `import_hook_closure`, but hooks to an `unsafe fn` which doesn't take
    /// reference to the original function.
    pub unsafe fn import_hook<H, L>(
        &mut self,
        library: L,
        hook: H,
        target: H::Fnptr,
    ) -> Patch
    where H: ExportHook,
          L: Into<Cow<'static, [u8]>>,
    {
        hook.import(self, library.into(), target)
    }


    /// Same as `import_hook_closure`, but hooks to an `unsafe fn` which can also call the
    /// original function.
    pub unsafe fn import_hook_opt<H, L>(
        &mut self,
        library: L,
        hook: H,
        target: H::OptFnptr,
    ) -> Patch
    where H: ExportHook,
          L: Into<Cow<'static, [u8]>>,
    {
        hook.import_opt(self, library.into(), target)
    }

    /// Allocates memory from patcher's executable memory heap.
    ///
    /// The allocated memory cannot be freed.
    pub fn exec_alloc(&mut self, size: usize) -> &'static mut [u8] {
        let mem = self.parent.exec_heap.allocate(size);
        unsafe { ::std::slice::from_raw_parts_mut(mem, size) }
    }

    /// Hooks a function with explicit entry, exit, and dynamic args.
    ///
    /// That is, this is supposed to work in cases where a function is inline of another
    /// function.
    #[cfg(target_arch = "x86")]
    pub unsafe fn inline_hook<H, T>(&mut self, _hook: H, decl: &InlineHook, target: T) -> Patch
    where H: HookDeclClosure<T>
    {
        let target = H::write_target_objects(target);
        let mut assembler = H::wrapper_assembler_inline(target.as_ptr());
        for &arg in &decl.args {
            assembler.add_arg(arg);
        }
        self.add_inline_hook(decl.entry, decl.exit, decl.inline_parent_entry, target, assembler)
    }
}

/// An exported function, identified either by its name or ordinal.
#[doc(hidden)]
pub enum Export<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
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
        self.address as *const T
    }
    pub unsafe fn mut_ptr(&self) -> *mut T {
        self.address as *mut T
    }
}

impl<T> ops::Deref for Variable<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { mem::transmute(self.address) }
    }
}

impl<T> ops::DerefMut for Variable<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { mem::transmute(self.address) }
    }
}

#[doc(hidden)]
/// A type which wraps a memory address and `Deref`s to `fn(...) -> ...`.
/// `Func` is meant to be created by the `whack_funcs!` macro, and to be used as it were
/// a static mutable function pointer.
pub struct Func<FnPtr>(pub AtomicUsize, pub PhantomData<FnPtr>);

impl<FnPtr> ops::Deref for Func<FnPtr> {
    type Target = FnPtr;
    fn deref(&self) -> &FnPtr {
        unsafe { &*(&self.0 as *const AtomicUsize as *const FnPtr) }
    }
}
