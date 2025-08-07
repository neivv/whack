#[macro_use]
extern crate whack;

use std::cell::Cell;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use whack::Patcher;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{self, HANDLE, INVALID_HANDLE_VALUE};

whack_export!(pub extern "system" CreateFileW(*const u16, u32, u32, u32, u32, u32, u32) -> HANDLE);
whack_export!(pub extern "system" CloseHandle(HANDLE) -> BOOL);
whack_export!(pub extern "system" GetProfileIntW(*const u16, *const u16, u32) -> u32);
whack_export!(pub extern "system" GetTickCount() -> u32);

thread_local!(static CLOSE_HANDLE_COUNT: Cell<u32> = const { Cell::new(0) });
thread_local!(static GET_PROFILE_INT_COUNT: Cell<u32> = const { Cell::new(0) });

unsafe fn close_handle_log(handle: HANDLE, orig: unsafe extern "C" fn(HANDLE) -> BOOL) -> BOOL {
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
    let mut root_patcher = Patcher::new();
    let create_file_patch;
    unsafe {
        let mut patcher = root_patcher.patch_exe(!0);
        let copy = value.clone();
        create_file_patch = patcher.import_hook_closure(&b"kernel32"[..], CreateFileW,
            move |filename: *const u16, a, b, c, d, e, f, orig| {
            let prev = copy.fetch_add(1, Ordering::SeqCst);
            let mut modified = vec![0; 1024];
            let mut pos = 0;
            while *filename.add(pos) != 0 {
                modified[pos] = *filename.add(pos);
                pos += 1;
            }
            modified[pos] = 0;
            if prev == 0 {
                modified[pos - 1] = b'c' as u16;
                modified[pos - 2] = b'b' as u16;
                modified[pos - 3] = b'a' as u16;
            }
            orig(modified.as_ptr(), a, b, c, d, e, f)
        });
        patcher.import_hook_opt(&b"kernel32"[..], CloseHandle, close_handle_log);
        patcher.import_hook(&b"kernel32"[..], GetProfileIntW, hook_without_orig);
    }
    unsafe {
        assert_eq!(value.load(Ordering::SeqCst), 0);
        let result = create_file("file.dat");
        assert_eq!(value.load(Ordering::SeqCst), 1);
        assert!(!std::path::Path::new("file.dat").exists());
        assert!(std::path::Path::new("file.abc").exists());
        let before = CLOSE_HANDLE_COUNT.with(|x| x.get());
        Foundation::CloseHandle(result);
        let after = CLOSE_HANDLE_COUNT.with(|x| x.get());
        assert_eq!(after, before + 1);
        let before = GET_PROFILE_INT_COUNT.with(|x| x.get());
        windows_sys::Win32::System::WindowsProgramming::GetProfileIntW(null_mut(), null_mut(), 0);
        let after = GET_PROFILE_INT_COUNT.with(|x| x.get());
        assert_eq!(after, before + 1);
        std::fs::remove_file("file.abc").unwrap();
    }
    {
        unsafe { root_patcher.disable_patch(&create_file_patch); }
    }
    value.store(0, Ordering::SeqCst);
    unsafe {
        let result = create_file("file.dat");
        assert!(std::path::Path::new("file.dat").exists());
        assert!(!std::path::Path::new("file.abc").exists());
        Foundation::CloseHandle(result);
        std::fs::remove_file("file.dat").unwrap();
    }
    {
        unsafe { root_patcher.enable_patch(&create_file_patch); }
    }
    value.store(0, Ordering::SeqCst);
    unsafe {
        let result = create_file("file.dat");
        assert!(!std::path::Path::new("file.dat").exists());
        assert!(std::path::Path::new("file.abc").exists());
        Foundation::CloseHandle(result);
        std::fs::remove_file("file.abc").unwrap();
    }
}

unsafe fn create_file(path: &str) -> HANDLE {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        self, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL,
    };
    let result = FileSystem::CreateFileW(
        winapi_str(path).as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null_mut(),
        FileSystem::CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        null_mut()
    );
    assert!(result != INVALID_HANDLE_VALUE);
    result
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
