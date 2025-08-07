#![allow(clippy::cmp_null)]

#[macro_use]
extern crate whack;
extern crate winapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use winapi::um::libloaderapi::{LoadLibraryW};
use winapi::um::memoryapi::{VirtualAlloc};
use winapi::um::winnt;

use whack::Patcher;
#[cfg(target_arch = "x86")]
mod funcs {
    pub const BASE: usize = 0x68100000;
    whack_funcs!(init_funcs, 0x68100000,
        0x68101610 => first(u32, u32, u32, u32, u32) -> u32;
        0x681015D4 => second(@eax u32, @ecx u32, @esi u32) -> u32;
        0x681015FA => third(@eax u32, @ecx u32, @edx u32, u32, @esi u32) -> u32;
    );
}

#[cfg(target_arch = "x86_64")]
mod funcs {
    pub const BASE: usize = 0x6C340000;
    whack_funcs!(init_funcs, 0x6C340000,
        0x6C3414F0 => first(u32, u32, u32, u32, u32) -> u32;
        0x6C3414A5 => second(@rbx u32, @rdi u32, @rsi u32) -> u32;
        0x6C3414D6 => third(@rbx u32, @rdi u32, @r15 u32, u32, @rsi u32) -> u32;
    );
}

#[cfg(target_arch = "x86")]
fn dll_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test_x86.dll")
}

#[cfg(target_arch = "x86_64")]
fn dll_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test_x86_64.dll")
}

#[cfg(target_arch = "x86")]
fn dll_name() -> &'static str {
    "test_x86"
}

#[cfg(target_arch = "x86_64")]
fn dll_name() -> &'static str {
    "test_x86_64"
}

#[test]
fn func_calls() {
    unsafe fn call_funcs() {
        let result = funcs::first(1, 2, 3, 4, 5);
        assert_eq!(result, 2505397621);
        let result = funcs::second(0x12, 0x34, 0x56);
        assert_eq!(result, 6);
        let result = funcs::third(0x12, 0x34, 0x56, 0x78, 0x9a);
        assert_eq!(result, 0x6f1c);
    }

    unsafe {
        // Test that it works even if the dll is relocated.
        VirtualAlloc(funcs::BASE as *mut _, 1, winnt::MEM_RESERVE, winnt::PAGE_NOACCESS);
        let lib = LoadLibraryW(winapi_str(dll_path()).as_ptr());
        assert!(lib != null_mut());

        {
            let mut patcher = Patcher::new();
            let mut patcher = patcher.patch_library(dll_name(), 0);
            funcs::init_funcs(&mut patcher);
            call_funcs();
        }
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
