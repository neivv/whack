use libc::types::os::arch::extra::{DWORD, MEMORY_BASIC_INFORMATION};
use libc::types::common::c95::c_void;
use libc::consts::os::extra::{PAGE_EXECUTE_READWRITE, GENERIC_WRITE, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL};
use libc::consts::os::extra::{CREATE_ALWAYS};
use libc::funcs::extra::kernel32::{VirtualProtect, VirtualQuery};
use kernel32::{GetModuleHandleW, CreateFileA, SetStdHandle};
use winapi::winbase::STD_ERROR_HANDLE;

use std::{mem, ptr};

pub fn nop() -> u8 {
    0x90
}

pub fn exe_addr() -> *const c_void {
    unsafe {
        mem::transmute(GetModuleHandleW(ptr::null()))
    }
}

/// Unprotects module, allowing its memory to be written and reapplies protection on drop.
/// As with most of the other utilities, it is not thread-safe to unprotect same module from multiple
/// threads.
pub struct MemoryProtection {
    protections: Vec<(*mut c_void, DWORD, DWORD)>,
}

impl MemoryProtection {
    pub fn new(start: *const c_void) -> MemoryProtection {
        let mut protections = Vec::new();
        unsafe {
            let mut mem_info: MEMORY_BASIC_INFORMATION = mem::uninitialized();
            let mut tmp: DWORD = 0;
            VirtualQuery(start, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32);
            while mem_info.Type == 0x1000000 { // 0x1000000 is MEM_IMAGE
                VirtualProtect(mem_info.BaseAddress, mem_info.RegionSize, PAGE_EXECUTE_READWRITE, &mut tmp);
                protections.push((mem_info.BaseAddress, mem_info.RegionSize, mem_info.Protect));
                let next = mem_info.BaseAddress.offset(mem_info.RegionSize as isize);
                VirtualQuery(next, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32);
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
            let mut tmp: DWORD = 0;
            for tp in self.protections.iter() {
                VirtualProtect(tp.0, tp.1, tp.2, &mut tmp);
            }
        }
    }
}

pub unsafe fn redirect_stderr(filename: &str) -> bool {
    let handle = CreateFileA(mem::transmute(filename.as_bytes().as_ptr()), GENERIC_WRITE, FILE_SHARE_READ,
        ptr::null_mut(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
    if handle != ptr::null_mut() {
        SetStdHandle(STD_ERROR_HANDLE, handle) != 0
    } else {
        false
    }
}
