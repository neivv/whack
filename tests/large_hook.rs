#[macro_use]
extern crate whack;
extern crate kernel32;
extern crate winapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use whack::Patcher;

#[cfg(target_arch = "x86")]
mod hook {
    whack_hooks!(0x637C0000,
        0x637C15C0 => Thirteen(u32, u32, u32, u32, u32,
                               u32, u32, u32, u32, u32,
                               u32, u32, u32) -> u32;
    );
}

#[cfg(target_arch = "x86_64")]
mod hook {
    whack_hooks!(0x6F440000,
        0x6F441490 => Thirteen(u32, u32, u32, u32, u32,
                               u32, u32, u32, u32, u32,
                               u32, u32, u32) -> u32;
    );
}

#[cfg(target_arch = "x86")]
fn dll_path() -> &'static str {
    "../../tests/test_large_x86.dll"
}

#[cfg(target_arch = "x86_64")]
fn dll_path() -> &'static str {
    "../../tests/test_large_x86_64.dll"
}

#[cfg(target_arch = "x86")]
fn dll_name() -> &'static str {
    "test_large_x86"
}

#[cfg(target_arch = "x86_64")]
fn dll_name() -> &'static str {
    "test_large_x86_64"
}

#[test]
fn large_hook() {
    unsafe {
        let lib = kernel32::LoadLibraryW(winapi_str(dll_path()).as_ptr());
        assert!(lib != null_mut());
        let thirteen = kernel32::GetProcAddress(lib, b"thirteen\0".as_ptr() as *const i8);
        assert!(thirteen != null_mut());

        let thirteen = std::mem::transmute::<_, extern fn(
            u32, u32, u32, u32, u32,
            u32, u32, u32, u32, u32,
            u32, u32, u32
        ) -> u32>(thirteen);

        let assert_nonhooked = || {
            let result = thirteen(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13);
            assert_eq!(result, 3067835428);
        };
        let assert_hooked = || {
            let result = thirteen(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13);
            assert_eq!(result, 132021325);
        };

        assert_nonhooked();

        let patcher = Patcher::new();
        {
            let mut patcher = patcher.lock().unwrap();
            let mut patch = patcher.patch_library(dll_name(), 0);
            patch.hook_closure(hook::Thirteen,
                move |a: u32, b: u32, c: u32, d: u32, e: u32,
                      f: u32, g: u32, h: u32, i: u32, j: u32,
                      k: u32, l: u32, m: u32,
                      orig: &Fn(_, _, _, _, _,
                                _, _, _, _, _,
                                _, _, _) -> _| {
                orig(a + b, b, c + d, d, e + f, f, g + h, h, i + j, j, k + l, l, m)
            });
        }

        assert_hooked();

        {
            let mut patcher = patcher.lock().unwrap();
            patcher.unpatch();
        }
        assert_nonhooked();
        {
            let mut patcher = patcher.lock().unwrap();
            patcher.repatch();
        }
        assert_hooked();
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}