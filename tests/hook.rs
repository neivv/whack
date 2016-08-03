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
    pub const BASE: usize = 0x68100000;
    declare_hooks!(0x68100000,
        0x68101610 => HookTest(u32, u32, u32, u32, u32) -> u32;
        0x681015D4 => HookReg(@eax u32, @ecx u32, @esi u32) -> u32;
        0x681015FA => HookRegStack(@eax u32, @ecx u32, @edx u32, u32, @esi u32) -> u32;
    );
}

#[cfg(target_arch = "x86_64")]
mod hook {
    pub const BASE: usize = 0x6C340000;
    declare_hooks!(0x6C340000,
        0x6C3414F0 => HookTest(u32, u32, u32, u32, u32) -> u32;
        0x6C3414A5 => HookReg(@rbx u32, @rdi u32, @rsi u32) -> u32;
        0x6C3414C7 => HookRegStack(@rbx u32, @rdi u32, @r15 u32, u32, @rsi u32) -> u32;
    );
}

#[allow(dead_code)]
mod hook_decl_tests {
    declare_hooks!(0x1234,
        0x1233 => Empty();
        0x1233 => EmptyRetInt() -> u32;
        0x1233 => NoRet(u32);
        0x1233 => StackSingle(@stack(1) u32);
        0x1233 => StackSecond(u32, @stack(0) u32);
        0x1233 => StackFirst(@stack(0) u32, u32);
    );
}

#[cfg(target_arch = "x86")]
#[allow(dead_code)]
mod hook_decl_tests_loc {
    declare_hooks!(0x1234,
        0x1233 => NoRet(@ecx u32);
        0x2514 => Implicit(u32, @edi u32);
        0x2514 => Implicit2(@esi u32, u32);
        0x1233 => StackAfterLoc(@ecx u32, @stack(0) u32);
    );
}

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod hook_decl_tests_loc {
    declare_hooks!(0x1234,
        0x1233 => NoRet(@rcx u32);
        0x2514 => Implicit(u32, @rdi u32);
        0x2514 => Implicit2(@rsi u32, u32);
        0x1233 => StackAfterLoc(@rcx u32, @stack(0) u32);
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
        let func2 = kernel32::GetProcAddress(lib, b"asm_reg_args_h\0".as_ptr() as *const i8);
        assert!(func2 != null_mut());
        let func3 = kernel32::GetProcAddress(lib, b"asm_reg_stack_args_h\0".as_ptr() as *const i8);
        assert!(func3 != null_mut());

        let func = std::mem::transmute::<_, extern fn(u32, u32, u32, u32, u32) -> u32>(func);
        let func2 = std::mem::transmute::<_, extern fn(u32, u32, u32) -> u32>(func2);
        let func3 = std::mem::transmute::<_, extern fn(u32, u32, u32, u32, u32) -> u32>(func3);

        let assert_nonhooked = || {
            let result = func(1, 2, 3, 4, 5);
            assert_eq!(result, 2505397621);
            let result = func2(0x12, 0x34, 0x56);
            assert_eq!(result, 6);
            let result = func3(0x12, 0x34, 0x56, 0x78, 0x9a);
            assert_eq!(result, 0x6f1c);
        };
        let assert_hooked = || {
            let result = func(1, 2, 3, 4, 5);
            assert_eq!(result, 3937053386);
            // TODO: x86_64 doesn't work
            if cfg!(target_arch = "x86") {
                let result = func2(0x12, 0x34, 0x56);
                assert_eq!(result, 0x26a);
                let result = func3(0x12, 0x34, 0x56, 0x78, 0x9a);
                assert_eq!(result, 0x4128);
            }
        };

        assert_nonhooked();

        let patcher = Patcher::new();
        {
            let mut patcher = patcher.lock().unwrap();
            patcher.patch_library(dll_name(), move |mut patch| {
                patch.hook_closure(hook::HookTest,
                    move |a: u32, b: u32, c: u32, d: u32, e: u32, orig: &Fn(_, _, _, _, _) -> _| {
                    orig(e, d, c, b, a)
                });
                patch.hook_closure(hook::HookReg,
                    move |a: u32, b: u32, c: u32, orig: &Fn(_, _, _) -> _| {
                    orig(c, b, a)
                });
                patch.hook_closure(hook::HookRegStack,
                    move |a: u32, b: u32, c: u32, d: u32, e: u32, orig: &Fn(_, _, _, _, _) -> _| {
                    orig(e, d, c, b, a)
                });
            });
        }

        assert_hooked();

        println!("Testing unpatching");
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
