#![allow(clippy::cmp_null, clippy::missing_transmute_annotations)]

extern crate whack;
extern crate winapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryW};
use winapi::um::memoryapi::{VirtualAlloc};
use winapi::um::winnt;

use whack::Patcher;

#[cfg(target_arch = "x86")]
mod addr {
    pub const BASE: usize = 0x68100000;
    // Patch u32
    pub const FUNC1: usize = 0x68101623;
    // Patch u8
    pub const FUNC2: usize = 0x681015D8;
    // Nop 2 bytes
    pub const FUNC3: usize = 0x68101600;
}

#[cfg(target_arch = "x86_64")]
mod addr {
    pub const BASE: usize = 0x6C340000;
    pub const FUNC1: usize = 0x6C3414F9;
    pub const FUNC2: usize = 0x6C3414AF;
    pub const FUNC3: usize = 0x6C3414E5;
}

#[cfg(target_arch = "x86")]
fn dll_path() -> &'static str {
    "../../tests/test_x86.dll"
}

#[cfg(target_arch = "x86_64")]
fn dll_path() -> &'static str {
    "../../tests/test_x86_64.dll"
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
fn replace() {
    unsafe {
        // Test that it works even if the dll is relocated.
        VirtualAlloc(addr::BASE as *mut _, 1, winnt::MEM_RESERVE, winnt::PAGE_NOACCESS);
        let lib = LoadLibraryW(winapi_str(dll_path()).as_ptr());
        assert!(lib != null_mut());
        let func = GetProcAddress(lib, b"test_func\0".as_ptr() as *const i8);
        assert!(func != null_mut());
        let func2 = GetProcAddress(lib, b"asm_reg_args_h\0".as_ptr() as *const i8);
        assert!(func2 != null_mut());
        let func3 = GetProcAddress(lib, b"asm_reg_stack_args_h\0".as_ptr() as *const i8);
        assert!(func3 != null_mut());

        let func = std::mem::transmute::<_, extern "C" fn(u32, u32, u32, u32, u32) -> u32>(func);
        let func2 = std::mem::transmute::<_, extern "C" fn(u32, u32, u32) -> u32>(func2);
        let func3 = std::mem::transmute::<_, extern "C" fn(u32, u32, u32, u32, u32) -> u32>(func3);

        let mut patches = vec![];

        let mut patcher = Patcher::new();
        {
            let mut patcher = patcher.patch_library(dll_name(), addr::BASE);
            let patch = patcher.replace_val(addr::FUNC1, 0x123u32);
            patches.push(patch);
            let patch = patcher.replace(addr::FUNC2, &[0x09]);
            patches.push(patch);
            let patch = patcher.nop(addr::FUNC3, 2);
            patches.push(patch);
        }

        let result = func(7, 9, 2, 10, 1);
        assert_eq!(result, 3937053371);
        let result = func2(11, 22, 33);
        assert_eq!(result, 5577);
        let result = func3(3, 3, 3, 3, 3);
        assert_eq!(result, 3);

        patcher.disable_patch(&patches[0]);
        patcher.disable_patch(&patches[2]);

        let result = func(7, 9, 2, 10, 1);
        assert_eq!(result, 3937053400);
        let result = func2(11, 22, 33);
        assert_eq!(result, 5577);
        let result = func3(3, 3, 3, 3, 3);
        assert_eq!(result, 33);
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
