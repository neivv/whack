#[macro_use]
extern crate whack;
extern crate kernel32;
extern crate winapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use whack::Patcher;
#[cfg(target_arch = "x86")]
mod hook {
    pub const BASE: usize = 0x6D9C0000;
    declare_hooks!(0x6D9C0000,
        0x6D9C15C0 => HookTest(u32, u32, u32, u32, u32) -> u32;
    );
}

#[cfg(target_arch = "x86_64")]
mod hook {
    pub const BASE: usize = 0x6D7C0000;
    declare_hooks!(0x6D7C0000,
        0x6D7C1480 => HookTest(u32, u32, u32, u32, u32) -> u32;
    );
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
fn address_hooking() {
    unsafe {
        // Test that it works even if the dll is relocated.
        kernel32::VirtualAlloc(hook::BASE as winapi::LPVOID, 1, winapi::MEM_RESERVE, 0);
        let lib = kernel32::LoadLibraryW(winapi_str(dll_path()).as_ptr());
        assert!(lib != null_mut());
        let func = kernel32::GetProcAddress(lib, b"test_func\0".as_ptr() as *const i8);
        assert!(func != null_mut());
        let func = std::mem::transmute::<_, extern fn(u32, u32, u32, u32, u32) -> u32>(func);
        let result = func(1, 2, 3, 4, 5);
        assert_eq!(result, 2505397621);
        let value = Rc::new(AtomicUsize::new(0));
        let patcher = Patcher::new();
        {
            let mut patcher = patcher.lock().unwrap();
            let copy = value.clone();
            patcher.patch_library(dll_name(), move |mut patch| {
                let copy = copy.clone();
                patch.hook(hook::HookTest,
                    move |a: u32, b: u32, c: u32, d: u32, e: u32, orig: &Fn(_, _, _, _, _) -> _| {
                    copy.fetch_add(1, Ordering::SeqCst);
                    orig(e, d, c, b, a)
                });
            });
        }
        let result = func(1, 2, 3, 4, 5);
        assert_eq!(result, 3937053386);
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
