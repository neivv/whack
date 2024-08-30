#![allow(clippy::cmp_null, clippy::missing_transmute_annotations)]

#[macro_use]
extern crate whack;
extern crate winapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryW};

use whack::Patcher;
#[cfg(target_arch = "x86")]
mod hook {
    whack_hooks!(stdcall, 0,
        0x0 => IsBadStringPtrW(*const u16, usize) -> u32;
    );
}

#[cfg(target_arch = "x86_64")]
mod hook {
    whack_hooks!(0,
        0x0 => IsBadStringPtrW(*const u16, usize) -> u32;
    );
}

#[test]
fn hook_kernel32() {
    unsafe {
        let lib = LoadLibraryW(winapi_str("kernel32").as_ptr());
        assert!(lib != null_mut());
        let func = GetProcAddress(lib, b"IsBadStringPtrW\0".as_ptr() as *const i8);
        assert!(func != null_mut());

        let func = std::mem::transmute::<_, extern "system" fn(*const u16, usize) -> u32>(func);

        let assert_nonhooked = || {
            let test_text = [
                b'a' as u16,
                b's' as u16,
                b'd' as u16,
                b'f' as u16,
                b'0' as u16,
                0u16,
            ];
            let ret = func(test_text.as_ptr(), 9999);
            assert_eq!(ret, 0);
        };
        let assert_hooked = || {
            let test_text = [
                b'a' as u16,
                b's' as u16,
                b'd' as u16,
                b'f' as u16,
                b'0' as u16,
                0u16,
            ];
            let ret = func(test_text.as_ptr(), 9999);
            assert_eq!(ret, 9999);
            let ret = func(test_text.as_ptr(), 2);
            assert_eq!(ret, 2);
        };

        assert_nonhooked();

        let mut patcher = Patcher::new();
        let patch = {
            let mut patch = patcher.patch_library("kernel32", 0);
            patch.hook_closure_address(
                hook::IsBadStringPtrW,
                move |_a, b, _orig| {
                    b as u32
                },
                func as usize - lib as usize,
            );
            patch.save_patch_group()
        };

        assert_hooked();

        println!("Testing unpatching");
        patcher.disable_patch(&patch);
        assert_nonhooked();
        patcher.enable_patch(&patch);
        assert_hooked();
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
