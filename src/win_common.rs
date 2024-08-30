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
    pub unsafe fn new(start: HMODULE) -> MemoryProtection {
        Self::new_main(start as *const u8, usize::MAX)
    }

    pub unsafe fn new_for_module(start: HMODULE) -> MemoryProtection {
        Self::new_main(start as *const u8, module_max_address(start as *const u8))
    }

    /// If the module's end is known, max_address should be provided, otherwise
    /// it can be usize::MAX.
    /// Unprotects range of committed pages with equivalent type but possibly different
    /// protections until noncommitted page or max_address is reached.
    /// I.e. will not unprotect two separate memory regions with unmapped memory in between,
    /// no matter what max_address is given.
    fn new_main(start: *const u8, max_address: usize) -> MemoryProtection {
        let start = start as *const _;
        let mut protections = Vec::new();
        if start as usize >= max_address {
            return MemoryProtection {
                protections,
            };
        }
        unsafe {
            let mut mem_info: winnt::MEMORY_BASIC_INFORMATION = mem::zeroed();
            let mem_info_size = mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>();
            let mut tmp = 0;
            // VirtualQuery returns amount of bytes actually written to MEMORY_BASIC_INFORMATION
            // parameter; So leaving out room for growing the parameter in future.
            // It probably is never grown and the last field there is Type which is needed
            // here, so as long as the struct definition on Rust side does not grow
            // this won't need do any tedious `offsetof(Type) + 4` stuff.
            let buf_size = VirtualQuery(start, &mut mem_info, mem_info_size);
            if buf_size < mem_info_size {
                panic!(
                    "Couldn't VirtualQuery memory {start:p}: {buf_size:x}/{:08x}",
                    GetLastError(),
                );
            }
            let init_type = mem_info.Type;
            while matches!(mem_info.State, winnt::MEM_COMMIT | winnt::MEM_RESERVE) &&
                mem_info.Type == init_type
            {
                let needs_unprotect = mem_info.State == winnt::MEM_COMMIT &&
                    match mem_info.Protect {
                        winnt::PAGE_EXECUTE_READ | winnt::PAGE_READONLY |
                            winnt::PAGE_EXECUTE => true,
                        _ => false,
                    };
                if needs_unprotect {
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

                let next = (mem_info.BaseAddress as *const u8).add(mem_info.RegionSize);
                if next as usize >= max_address {
                    break;
                }
                let buf_size = VirtualQuery(next as *const _, &mut mem_info, mem_info_size);
                if buf_size < mem_info_size {
                    panic!(
                        "Couldn't VirtualQuery memory {next:p}: {buf_size:x}/{:08x}",
                        GetLastError(),
                    );
                }
            }
        }
        MemoryProtection {
            protections,
        }
    }
}

unsafe fn module_max_address(base: *const u8) -> usize {
    let pe_header_offset = *(base.add(0x3c) as *mut u32);
    let pe_header = base.add(pe_header_offset as usize);
    let section_count = (pe_header.add(6) as *mut u16).read_unaligned();
    let opt_header_size = (pe_header.add(0x14) as *mut u16).read_unaligned();
    let section_offset = 0x18 + opt_header_size as usize;

    let mut max = base.add(0x1000) as usize;
    for i in 0..section_count {
        let section = pe_header.add(section_offset + 0x28 * i as usize);

        let rva = (section.add(0xc) as *mut u32).read_unaligned();
        let virtual_size = (section.add(0x8) as *mut u32).read_unaligned();
        let end = (base as usize).wrapping_add(rva as usize).wrapping_add(virtual_size as usize);
        max = max.max(end);
    }
    max
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
