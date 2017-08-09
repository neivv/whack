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

use Export;
use pe;

pub type LibraryHandle = HMODULE;
pub type LibraryName = Vec<u16>;

pub fn nop() -> u8 {
    0x90
}

pub fn library_name<T: AsRef<OsStr>>(input: T) -> LibraryName {
    winapi_str(input)
}

pub fn library_name_to_handle(name: &LibraryName) -> Option<LibraryHandle> {
    let result = unsafe { kernel32::GetModuleHandleW(name.as_ptr()) };
    if result == ptr::null_mut() { None } else { Some(result) }
}

pub fn lib_handle_equals_name(handle: LibraryHandle, name: &LibraryName) -> bool {
    unsafe { kernel32::GetModuleHandleW(name.as_ptr()) == handle }
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

unsafe impl Send for ExecutableHeap {
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

    pub fn free(&mut self, ptr: *mut u8) {
        unsafe { kernel32::HeapFree(self.handle, 0, ptr as winapi::LPVOID); }
    }
}

pub fn exe_handle() -> HMODULE {
    unsafe {
        kernel32::GetModuleHandleW(ptr::null())
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
        // This currently may go over to the next module if they are next to each other..
        // Should have min and max addresses instead.
        let start = start as winapi::LPVOID;
        let mut protections = Vec::new();
        unsafe {
            let mut mem_info: winapi::MEMORY_BASIC_INFORMATION = mem::uninitialized();
            let mut tmp = 0;
            kernel32::VirtualQuery(start, &mut mem_info, mem::size_of_val(&mem_info) as _);
            let init_type = mem_info.Type;
            while mem_info.Type == init_type {
                if mem_info.State == winapi::MEM_COMMIT {
                    let ok = kernel32::VirtualProtect(
                        mem_info.BaseAddress,
                        mem_info.RegionSize,
                        winapi::PAGE_EXECUTE_READWRITE,
                        &mut tmp,
                    );
                    if ok == 0 {
                        panic!(
                            "Couldn't VirtualProtect memory {:p}:{:x} from {:x}: {}",
                            mem_info.BaseAddress,
                            mem_info.RegionSize,
                            mem_info.Protect,
                            Win32Error::new(),
                        );
                    }
                    let address = mem_info.BaseAddress as *mut c_void;
                    protections.push((address, mem_info.RegionSize, mem_info.Protect));
                }
                let next = mem_info.BaseAddress.offset(mem_info.RegionSize as isize);
                kernel32::VirtualQuery(next, &mut mem_info, mem::size_of_val(&mem_info) as _);
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

pub unsafe fn import_addr(module: HMODULE, func_dll: &[u8], func: &Export) -> Option<*mut usize>
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

    pe::import_ptr(module as usize, &func_dll_with_extension, func)
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
