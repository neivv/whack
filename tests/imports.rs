#[macro_use]
extern crate whack;
extern crate kernel32;
extern crate winapi;

use std::cell::Cell;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use whack::Patcher;

export_hook!(pub extern "system" CreateFileW(*const u16, u32, u32, u32, u32, u32, u32) -> winapi::HANDLE);
export_hook!(pub extern "system" CloseHandle(winapi::HANDLE) -> winapi::BOOL);
export_hook!(pub extern "system" GetProfileIntW(*const u16, *const u16, u32) -> u32);

thread_local!(static CLOSE_HANDLE_COUNT: Cell<u32> = Cell::new(0));
thread_local!(static GET_PROFILE_INT_COUNT: Cell<u32> = Cell::new(0));

unsafe fn close_handle_log(handle: winapi::HANDLE, orig: &Fn(winapi::HANDLE) -> winapi::BOOL) -> winapi::BOOL {
    CLOSE_HANDLE_COUNT.with(|x| x.set(x.get() + 1));
    orig(handle)
}

unsafe fn hook_without_orig(_a: *const u16, _b: *const u16, _c: u32) -> u32 {
    GET_PROFILE_INT_COUNT.with(|x| x.set(x.get() + 1));
    0
}

#[test]
fn import_hooking() {
    while std::path::Path::new("file.dat").exists() {
        std::fs::remove_file("file.dat").unwrap();
    }
    while std::path::Path::new("file.abc").exists() {
        std::fs::remove_file("file.abc").unwrap();
    }

    let value = Rc::new(AtomicUsize::new(0));
    let root_patcher = Patcher::new();
    {
        let mut locked = root_patcher.lock().unwrap();
        let mut patcher = locked.patch_all_modules();
        let copy = value.clone();
        patcher.import_hook_closure(b"kernel32"[..].into(), CreateFileW,
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
        patcher.import_hook_opt(b"kernel32"[..].into(), CloseHandle, close_handle_log);
        patcher.import_hook(b"kernel32"[..].into(), GetProfileIntW, hook_without_orig);
        patcher.apply();
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
        let before = CLOSE_HANDLE_COUNT.with(|x| x.get());
        kernel32::CloseHandle(result);
        let after = CLOSE_HANDLE_COUNT.with(|x| x.get());
        assert_eq!(after, before + 1);
        let before = GET_PROFILE_INT_COUNT.with(|x| x.get());
        kernel32::GetProfileIntW(null_mut(), null_mut(), 0);
        let after = GET_PROFILE_INT_COUNT.with(|x| x.get());
        assert_eq!(after, before + 1);
        std::fs::remove_file("file.abc").unwrap();
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
