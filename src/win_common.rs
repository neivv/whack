//! Common windows code for both x86 and x86_64.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use libc::c_void;

use winapi::shared::minwindef::HMODULE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::heapapi::{HeapAlloc, HeapCreate, HeapFree};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::winnt::{self, HANDLE};

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
    let result = unsafe { GetModuleHandleW(name.as_ptr()) };
    if result.is_null() { None } else { Some(result) }
}

pub fn lib_handle_equals_name(handle: LibraryHandle, name: &LibraryName) -> bool {
    unsafe { GetModuleHandleW(name.as_ptr()) == handle }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}

pub struct ExecutableHeap {
    handle: HANDLE,
}

unsafe impl Send for ExecutableHeap {
}

impl ExecutableHeap {
    pub fn new() -> ExecutableHeap {
        ExecutableHeap {
            handle: unsafe { HeapCreate(winnt::HEAP_CREATE_ENABLE_EXECUTE, 0, 0) },
        }
    }

    pub fn allocate(&mut self, size: usize) -> *mut u8 {
        unsafe { HeapAlloc(self.handle, 0, size) as *mut u8 }
    }

    pub fn free(&mut self, ptr: *mut u8) {
        unsafe { HeapFree(self.handle, 0, ptr as *mut _); }
    }
}

pub fn exe_handle() -> HMODULE {
    unsafe {
        GetModuleHandleW(ptr::null())
    }
}

pub fn library_handle(lib: &OsStr) -> HMODULE {
    unsafe {
        GetModuleHandleW(winapi_str(lib).as_ptr())
    }
}

/// Unprotects module, allowing its memory to be written and reapplies protection on drop.
/// As with most of the other utilities, it is not thread-safe to unprotect same module from multiple
/// threads.
#[must_use]
pub struct MemoryProtection {
    protections: Vec<(*mut c_void, usize, u32)>,
}

impl MemoryProtection {
    pub fn new(start: HMODULE) -> MemoryProtection {
        // This currently may go over to the next module if they are next to each other..
        // Should have min and max addresses instead.
        let start = start as *const _;
        let mut protections = Vec::new();
        unsafe {
            let mut mem_info: winnt::MEMORY_BASIC_INFORMATION = mem::zeroed();
            let mut tmp = 0;
            VirtualQuery(start, &mut mem_info, mem::size_of_val(&mem_info) as _);
            let init_type = mem_info.Type;
            while mem_info.Type == init_type {
                if mem_info.State == winnt::MEM_COMMIT {
                    let ok = VirtualProtect(
                        mem_info.BaseAddress,
                        mem_info.RegionSize,
                        winnt::PAGE_EXECUTE_READWRITE,
                        &mut tmp,
                    );
                    if ok == 0 {
                        panic!(
                            "Couldn't VirtualProtect memory {:p}:{:x} from {:x}: {:08x}",
                            mem_info.BaseAddress,
                            mem_info.RegionSize,
                            mem_info.Protect,
                            GetLastError(),
                        );
                    }
                    let address = mem_info.BaseAddress as *mut c_void;
                    protections.push((address, mem_info.RegionSize, mem_info.Protect));
                }
                let next = (mem_info.BaseAddress as *const u8)
                    .offset(mem_info.RegionSize as isize);
                VirtualQuery(next as *const _, &mut mem_info, mem::size_of_val(&mem_info) as _);
            }
        }
        MemoryProtection {
            protections,
        }
    }
}

impl Drop for MemoryProtection {
    fn drop(&mut self) {
        unsafe {
            let mut tmp = 0;
            for tp in &self.protections {
                VirtualProtect(tp.0 as *mut _, tp.1, tp.2, &mut tmp);
            }
        }
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
