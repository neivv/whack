//! Common windows code for both x86 and x86_64.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr;
use std::slice;

use libc::c_void;

use kernel32;
use rust_win32error::Win32Error;
use winapi::{self, HANDLE, HMODULE};

use {AddressHookClosure, AnyModulePatch, Patcher, Export, ExportHookClosure};
use pe;

pub enum PatchType {
    // Import addr (relative from base), original, hook
    Import(usize, usize, usize),
    // Addr (relative from base), wrapper, orig_size
    // The orig code is stored at `wrapper - orig_size`.
    BasicHook(usize, usize, usize),
}

impl PatchType {
    pub unsafe fn enable(&self, base: usize) {
        match *self {
            PatchType::Import(offset, _, val) => {
                let addr = (base + offset) as *mut usize;
                *addr = val;
            }
            PatchType::BasicHook(offset, wrapper, _) => {
                let addr = (base + offset) as *mut u8;
                ::platform::write_jump(addr, wrapper as *const u8);
            }
        }
    }

    pub unsafe fn disable(&self, base: usize) {
        match *self {
            PatchType::Import(offset, val, _) => {
                let addr = (base + offset) as *mut usize;
                *addr = val;
            }
            PatchType::BasicHook(offset, wrapper, size) => {
                let addr = (base + offset) as *mut u8;
                ptr::copy_nonoverlapping((wrapper - size) as *const u8, addr, size);
            }
        }
    }
}

pub type LibraryHandle = HMODULE;

mod hook {
    use winapi::{HANDLE, HMODULE};
    export_hook!(pub extern "system" LoadLibraryA(*const i8) -> HMODULE);
    export_hook!(pub extern "system" LoadLibraryExA(*const i8, HANDLE, u32) -> HMODULE);
    export_hook!(pub extern "system" LoadLibraryW(*const u16) -> HMODULE);
    export_hook!(pub extern "system" LoadLibraryExW(*const u16, HANDLE, u32) -> HMODULE);
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}

unsafe fn from_winapi_str(input: *const u16) -> OsString {
    let mut end = 0;
    while *input.offset(end) != 0 {
        end += 1;
    }
    OsStringExt::from_wide(slice::from_raw_parts(input, end as usize))
}

pub struct ExecutableHeap {
    handle: HANDLE,
}

impl ExecutableHeap {
    pub fn new() -> ExecutableHeap {
        ExecutableHeap {
            handle: unsafe { kernel32::HeapCreate(winapi::HEAP_CREATE_ENABLE_EXECUTE, 0, 0) },
        }
    }
    pub fn allocate(&mut self, size: usize) -> *mut u8 {
        unsafe { kernel32::HeapAlloc(self.handle, 0, size as winapi::SIZE_T) as *mut u8 }
    }
}

pub fn exe_handle() -> HMODULE {
    unsafe {
        kernel32::GetModuleHandleW(ptr::null())
    }
}

fn module_name(handle: HMODULE) -> Option<OsString> {
    unsafe {
        let mut buf_size = 128;
        let mut buf = Vec::with_capacity(buf_size);
        loop {
            let result = kernel32::GetModuleFileNameW(handle, buf.as_mut_ptr(), buf_size as u32);
            match result {
                n if n == buf_size as u32 => {
                    // reserve does not guarantee to reserve exactly specified size,
                    // unlike with_capacity
                    let reserve_amt = buf.capacity();
                    buf.reserve(reserve_amt);
                    buf_size = buf.capacity();
                }
                0 => {
                    // Error
                    return None;
                }
                n => {
                    return Some(OsString::from_wide(::std::slice::from_raw_parts(buf.as_ptr(), n as usize)));
                }
            }
        }
    }
}

pub fn library_handle(lib: &OsStr) -> HMODULE {
    unsafe {
        kernel32::GetModuleHandleW(winapi_str(lib).as_ptr())
    }
}

/// Unprotects module, allowing its memory to be written and reapplies protection on drop.
/// As with most of the other utilities, it is not thread-safe to unprotect same module from multiple
/// threads.
#[must_use]
pub struct MemoryProtection {
    protections: Vec<(*mut c_void, winapi::SIZE_T, winapi::DWORD)>,
}

impl MemoryProtection {
    pub fn new(start: HMODULE) -> MemoryProtection {
        let start = start as winapi::LPVOID;
        let mut protections = Vec::new();
        unsafe {
            let mut mem_info: winapi::MEMORY_BASIC_INFORMATION = mem::uninitialized();
            let mut tmp = 0;
            kernel32::VirtualQuery(start, &mut mem_info, mem::size_of_val(&mem_info) as winapi::SIZE_T);
            while mem_info.Type == winapi::MEM_IMAGE {
                kernel32::VirtualProtect(mem_info.BaseAddress,
                                         mem_info.RegionSize,
                                         winapi::PAGE_EXECUTE_READWRITE,
                                         &mut tmp);
                protections.push((mem_info.BaseAddress as *mut c_void, mem_info.RegionSize, mem_info.Protect));
                let next = mem_info.BaseAddress.offset(mem_info.RegionSize as isize);
                kernel32::VirtualQuery(next, &mut mem_info, mem::size_of_val(&mem_info) as winapi::SIZE_T);
            }
        }
        MemoryProtection {
            protections: protections,
        }
    }
}

impl Drop for MemoryProtection {
    fn drop(&mut self) {
        unsafe {
            let mut tmp = 0;
            for tp in self.protections.iter() {
                kernel32::VirtualProtect(tp.0 as winapi::LPVOID, tp.1, tp.2, &mut tmp);
            }
        }
    }
}

pub unsafe fn redirect_stderr(filename: &Path) -> bool {
    let handle = kernel32::CreateFileW(winapi_str(filename).as_ptr(),
                                       winapi::GENERIC_WRITE,
                                       winapi::FILE_SHARE_READ,
                                       ptr::null_mut(),
                                       winapi::CREATE_ALWAYS,
                                       winapi::FILE_ATTRIBUTE_NORMAL,
                                       ptr::null_mut());
    if handle != ptr::null_mut() {
        kernel32::SetStdHandle(winapi::STD_ERROR_HANDLE, handle) != 0
    } else {
        false
    }
}

// Separate for `custom_calling_convention`.
pub unsafe fn hook_wrapper<H: AddressHookClosure<T>, T>(func: Option<*const u8>,
                                                        target: T,
                                                        exec_heap: &mut ExecutableHeap,
                                                        preserve_regs: bool,
                                                       ) -> (usize, usize)
{
    let result = H::write_wrapper(preserve_regs, target, func, exec_heap);
    (result.0 as usize, result.1)
}

pub unsafe fn jump_hook<H: AddressHookClosure<T>, T>(base: usize,
                                                     target: T,
                                                     exec_heap: &mut ExecutableHeap,
                                                     preserve_regs: bool,
                                                    ) -> PatchType
{
    let func = H::address(base);
    let (wrapper, orig_ins_len) =
        hook_wrapper::<H, T>(Some(func as *const u8), target, exec_heap, preserve_regs);
    PatchType::BasicHook(func - base, wrapper, orig_ins_len)
}

pub unsafe fn import_hook<H: ExportHookClosure<T>, T>(base_addr: usize,
                                func_dll: &[u8],
                                func: Export,
                                target: T,
                                exec_heap: &mut ExecutableHeap
                               ) -> Option<PatchType>
{
    let func_dll_with_extension = {
        let has_extension = {
            if func_dll.len() <= 4 {
                false
            } else {
                func_dll[func_dll.len() - 4] == b'.'
            }
        };
        if has_extension {
            Cow::Borrowed(func_dll)
        } else {
            Cow::Owned(func_dll.iter().cloned().chain(b".dll".iter().cloned()).collect())
        }
    };

    pe::import_ptr(base_addr, &func_dll_with_extension, func).map(|ptr| {
        let orig = *ptr;
        let wrapper_memory = H::write_wrapper(false, target, Some(orig as *mut u8), exec_heap).0;
        PatchType::Import(ptr as usize - base_addr, orig, wrapper_memory as usize)
    })
}

/// Patches the imports of module given by `get_patch()`
pub fn apply_library_loading_hook(patcher: &Patcher, mut patch: AnyModulePatch) {
    let patcher_clone = patcher.clone_ref();
    patch.import_hook_closure(b"kernel32", hook::LoadLibraryA,
        move |filename, orig: &Fn(_) -> _| {
        let already_loaded = unsafe { kernel32::GetModuleHandleA(filename) } != ptr::null_mut();
        let result = orig(filename);
        if !already_loaded {
            hook_new_library(result, &patcher_clone);
        }
        result
    });
    let patcher_clone = patcher.clone_ref();
    patch.import_hook_closure(b"kernel32", hook::LoadLibraryExA,
        move |filename, file, flags, orig: &Fn(_, _, _) -> _| {
        let already_loaded = unsafe { kernel32::GetModuleHandleA(filename) } != ptr::null_mut();
        let result = orig(filename, file, flags);
        if !already_loaded {
            hook_new_library(result, &patcher_clone);
        }
        result
    });
    let patcher_clone = patcher.clone_ref();
    patch.import_hook_closure(b"kernel32", hook::LoadLibraryW,
        move |filename, orig: &Fn(_) -> _| {
        let already_loaded = unsafe { kernel32::GetModuleHandleW(filename) } != ptr::null_mut();
        let result = orig(filename);
        if !already_loaded {
            hook_new_library(result, &patcher_clone);
        }
        result
    });
    let patcher_clone = patcher.clone_ref();
    patch.import_hook_closure(b"kernel32", hook::LoadLibraryExW,
        move |filename, file, flags, orig: &Fn(_, _, _) -> _| {
        let already_loaded = unsafe { kernel32::GetModuleHandleW(filename) } != ptr::null_mut();
        let result = orig(filename, file, flags);
        if !already_loaded {
            hook_new_library(result, &patcher_clone);
        }
        result
    });
}

fn hook_new_library(lib: HMODULE, patcher: &Patcher) {
    unsafe {
        let mut patcher = patcher.lock().unwrap();
        let lib_name = module_name(lib).unwrap();
        patcher.patch_library(&lib_name, |mut patch| {
            for &(ref apply_patches, ref patch_uid) in patch.automatic_library_patches {
                apply_patches(patch.any_module_downgrade(**patch_uid));
            }
        });
    }
}

/// Calls `callback` with names of each library loaded by current process.
pub fn for_libraries<Cb: FnMut(&OsStr, HMODULE)>(mut callback: Cb) -> Result<(), Win32Error> {
    unsafe {
        let handle = kernel32::CreateToolhelp32Snapshot(winapi::TH32CS_SNAPMODULE, 0);
        if handle == winapi::INVALID_HANDLE_VALUE {
            return Err(Win32Error::new());
        }
        defer!({ kernel32::CloseHandle(handle); });
        let mut entry = winapi::MODULEENTRY32W {
            dwSize: mem::size_of::<winapi::MODULEENTRY32W>() as u32,
            .. mem::zeroed()
        };
        let ok = kernel32::Module32FirstW(handle, &mut entry);
        if ok == winapi::FALSE {
            return Err(Win32Error::new());
        }
        let exe_handle = exe_handle();
        loop {
            if entry.hModule != exe_handle {
                let name = from_winapi_str(entry.szModule.as_ptr());
                callback(&name, entry.hModule)
            }
            let ok = kernel32::Module32NextW(handle, &mut entry);
            if ok == winapi::FALSE {
                let err = Win32Error::new();
                if err.get_error_code() == winapi::ERROR_NO_MORE_FILES {
                    return Ok(());
                } else {
                    return Err(err);
                }
            }
        }
    }
}

#[test]
fn test_for_libraries() {
    use std::ascii::AsciiExt;
    let mut vec = Vec::new();
    for_libraries(|lib, _handle| vec.push(lib.to_os_string())).unwrap();
    assert!(vec
            .iter()
            .find(|&x| x.to_str()
                  .map(|s| s.eq_ignore_ascii_case("kernel32.dll"))
                  .unwrap_or(false))
            .is_some());
    assert!(vec
            .iter()
            .find(|&x| x.to_str()
                  .map(|s| s[s.len() - 4..].eq_ignore_ascii_case(".exe"))
                  .unwrap_or(false))
            .is_none());
}
