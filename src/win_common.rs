//! Common windows code for both x86 and x86_64.

use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::raw::c_void;
use std::ptr;

use winapi::shared::minwindef::HMODULE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
use winapi::um::winnt::{self};

use crate::Export;
use crate::pe;

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
    let input = input.as_ref();
    let iter = input.encode_wide();
    let mut out = Vec::with_capacity(iter.size_hint().0 + 1);
    out.extend(iter);
    out.push(0);
    out
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
            let process = GetCurrentProcess();
            for tp in &self.protections {
                VirtualProtect(tp.0 as *mut _, tp.1, tp.2, &mut tmp);
                FlushInstructionCache(process, tp.0 as *const _, tp.1);
            }
        }
    }
}

pub unsafe fn import_addr(module: HMODULE, func_dll: &[u8], func: &Export) -> Option<*mut usize>
{
    let mut buf;
    let func_dll_with_extension = {
        let has_extension = {
            if func_dll.len() <= 4 {
                false
            } else {
                func_dll[func_dll.len() - 4] == b'.'
            }
        };
        if has_extension {
            func_dll
        } else {
            buf = Vec::with_capacity(func_dll.len() + 4);
            buf.extend_from_slice(func_dll);
            buf.extend_from_slice(b".dll");
            &buf[..]
        }
    };

    pe::import_ptr(module as usize, func_dll_with_extension, func)
}
