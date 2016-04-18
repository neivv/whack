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

export_hook!(pub extern "system" CreateFileW(*const u16, u32, u32, u32, u32, u32, u32) -> winapi::HANDLE);

#[test]
fn import_hooking() {
    while std::path::Path::new("file.dat").exists() {
        std::fs::remove_file("file.dat").unwrap();
    }
    while std::path::Path::new("file.abc").exists() {
        std::fs::remove_file("file.abc").unwrap();
    }

    let value = Rc::new(AtomicUsize::new(0));
    let patcher = Patcher::new();
    {
        let mut patcher = patcher.lock().unwrap();
        let copy = value.clone();
        patcher.patch_modules(move |mut patch| {
            let copy = copy.clone();
            patch.import_hook(b"kernel32", CreateFileW,
                move |filename: *const u16, a, b, c, d, e, f, orig: &Fn(_, _, _, _, _, _, _) -> _| {
                let prev = copy.fetch_add(1, Ordering::SeqCst);
                let mut modified = vec![0; 1024];
                let mut pos = 0;
                unsafe {
                    while *filename.offset(pos as isize) != 0 {
                        modified[pos] = *filename.offset(pos as isize);
                        pos += 1;
                    }
                }
                modified[pos] = 0;
                if prev == 0 {
                    modified[pos - 1] = b'c' as u16;
                    modified[pos - 2] = b'b' as u16;
                    modified[pos - 3] = b'a' as u16;
                }
                orig(modified.as_ptr(), a, b, c, d, e, f)
            });
        });
    }
    unsafe {
        assert_eq!(value.load(Ordering::SeqCst), 0);
        let result = kernel32::CreateFileW(winapi_str("file.dat").as_ptr(),
                              winapi::GENERIC_READ | winapi::GENERIC_WRITE,
                              winapi::FILE_SHARE_READ | winapi::FILE_SHARE_WRITE,
                              null_mut(),
                              winapi::CREATE_NEW,
                              winapi::FILE_ATTRIBUTE_NORMAL,
                              null_mut());
        assert!(result != winapi::INVALID_HANDLE_VALUE);
        assert_eq!(value.load(Ordering::SeqCst), 1);
        assert!(!std::path::Path::new("file.dat").exists());
        assert!(std::path::Path::new("file.abc").exists());
        kernel32::CloseHandle(result);
        std::fs::remove_file("file.abc").unwrap();
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
