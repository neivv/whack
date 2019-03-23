#[macro_use]
extern crate whack;
extern crate winapi;

use std::cell::Cell;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use whack::Patcher;

use winapi::shared::minwindef::BOOL;
use winapi::um::fileapi;
use winapi::um::handleapi::{self, INVALID_HANDLE_VALUE};
use winapi::um::sysinfoapi;
use winapi::um::winbase;
use winapi::um::winnt::{self, HANDLE};

whack_export!(pub extern "system" CreateFileW(*const u16, u32, u32, u32, u32, u32, u32) -> HANDLE);
whack_export!(pub extern "system" CloseHandle(HANDLE) -> BOOL);
whack_export!(pub extern "system" GetProfileIntW(*const u16, *const u16, u32) -> u32);
whack_export!(pub extern "system" GetTickCount() -> u32);

thread_local!(static CLOSE_HANDLE_COUNT: Cell<u32> = Cell::new(0));
thread_local!(static GET_PROFILE_INT_COUNT: Cell<u32> = Cell::new(0));
thread_local!(static TICK_COUNT_CALLS: Cell<u32> = Cell::new(0));

unsafe fn close_handle_log(handle: HANDLE, orig: &Fn(HANDLE) -> BOOL) -> BOOL {
    CLOSE_HANDLE_COUNT.with(|x| x.set(x.get() + 1));
    orig(handle)
}

unsafe fn hook_without_orig(_a: *const u16, _b: *const u16, _c: u32) -> u32 {
    GET_PROFILE_INT_COUNT.with(|x| x.set(x.get() + 1));
    0
}


fn add_tick_count_call() {
    TICK_COUNT_CALLS.with(|x| x.set(x.get() + 1));
}

fn get_tick_count_calls() -> u32 {
    TICK_COUNT_CALLS.with(|x| x.get())
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
    let create_file_patch;
    let tick_count_patch;
    {
        let mut locked = root_patcher.lock().unwrap();
        {
            let mut exe = locked.patch_exe(!0);
            tick_count_patch = exe.import_hook_closure(&b"kernel32"[..], GetTickCount,
                move |orig: &Fn() -> _| {
                add_tick_count_call();
                orig()
            });
            exe.apply_disabled();
        }
        let mut patcher = locked.patch_exe(!0);
        let copy = value.clone();
        create_file_patch = patcher.import_hook_closure(&b"kernel32"[..], CreateFileW,
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
        patcher.import_hook_opt(&b"kernel32"[..], CloseHandle, close_handle_log);
        patcher.import_hook(&b"kernel32"[..], GetProfileIntW, hook_without_orig);
        patcher.apply();
    }
    unsafe {
        assert_eq!(value.load(Ordering::SeqCst), 0);
        let result = create_file("file.dat");
        assert_eq!(value.load(Ordering::SeqCst), 1);
        assert!(!std::path::Path::new("file.dat").exists());
        assert!(std::path::Path::new("file.abc").exists());
        let before = CLOSE_HANDLE_COUNT.with(|x| x.get());
        handleapi::CloseHandle(result);
        let after = CLOSE_HANDLE_COUNT.with(|x| x.get());
        assert_eq!(after, before + 1);
        let before = GET_PROFILE_INT_COUNT.with(|x| x.get());
        winbase::GetProfileIntW(null_mut(), null_mut(), 0);
        let after = GET_PROFILE_INT_COUNT.with(|x| x.get());
        assert_eq!(after, before + 1);
        std::fs::remove_file("file.abc").unwrap();
    }
    {
        let mut locked = root_patcher.lock().unwrap();
        unsafe { locked.disable_patch(&create_file_patch); }
    }
    value.store(0, Ordering::SeqCst);
    unsafe {
        let result = create_file("file.dat");
        assert!(std::path::Path::new("file.dat").exists());
        assert!(!std::path::Path::new("file.abc").exists());
        handleapi::CloseHandle(result);
        std::fs::remove_file("file.dat").unwrap();
    }
    {
        let mut locked = root_patcher.lock().unwrap();
        unsafe { locked.enable_patch(&create_file_patch); }
    }
    value.store(0, Ordering::SeqCst);
    unsafe {
        let result = create_file("file.dat");
        assert!(!std::path::Path::new("file.dat").exists());
        assert!(std::path::Path::new("file.abc").exists());
        handleapi::CloseHandle(result);
        std::fs::remove_file("file.abc").unwrap();
    }
    unsafe { sysinfoapi::GetTickCount(); }
    assert_eq!(get_tick_count_calls(), 0);
    {
        let mut locked = root_patcher.lock().unwrap();
        unsafe { locked.enable_patch(&tick_count_patch); }
    }
    let prev = get_tick_count_calls();
    unsafe { sysinfoapi::GetTickCount(); }
    assert_eq!(get_tick_count_calls(), prev + 1);
}

unsafe fn create_file(path: &str) -> HANDLE {
    let result = fileapi::CreateFileW(
        winapi_str(path).as_ptr(),
        winnt::GENERIC_READ | winnt::GENERIC_WRITE,
        winnt::FILE_SHARE_READ | winnt::FILE_SHARE_WRITE,
        null_mut(),
        fileapi::CREATE_NEW,
        winnt::FILE_ATTRIBUTE_NORMAL,
        null_mut()
    );
    assert!(result != INVALID_HANDLE_VALUE);
    result
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}
