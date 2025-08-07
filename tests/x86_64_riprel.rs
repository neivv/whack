#![allow(clippy::identity_op, clippy::bool_comparison)]

#[macro_use]
#[cfg(target_arch = "x86_64")]
extern crate whack;

#[cfg(target_arch = "x86_64")]
mod test {
    use std::mem;
    use std::ptr::{self, null_mut};
    use std::sync::atomic::{AtomicU32};

    use windows_sys::Win32::System::{
        Memory::{VirtualAlloc, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE},
    };

    use whack::Patcher;

    whack_hooks!(0,
        0 => GetRef() -> *mut u32;
        0 => ReadAny() -> u32;
        0 => Write(u32);
        0 => BinaryFunc(u32, u32) -> u32;
    );

    #[derive(Copy, Clone)]
    struct LoadedCode {
        base: *mut u8,
        get_ref: unsafe extern "C" fn() -> *mut u32,
        cmp_nonzero: unsafe extern "C" fn() -> u32,
        cmp_nonzero_byte: unsafe extern "C" fn() -> u32,
        read_value: unsafe extern "C" fn() -> u32,
        write_value: unsafe extern "C" fn(u32),
        indirected_read: unsafe extern "C" fn() -> u32,
        // if a1 != 0 { a2 * 2 * a1 as u16 - global } else { a2 }
        early_jump: unsafe extern "C" fn(u32, u32) -> u32,
        // Same but also if a1 & 0x8000_0000
        early_jump_twice: unsafe extern "C" fn(u32, u32) -> u32,
        with_stack_frame_entry: unsafe extern "C" fn(u32, u32) -> u32,
        with_stack_frame_middle: unsafe extern "C" fn() -> !,
    }

    unsafe impl Sync for LoadedCode {}
    unsafe impl Send for LoadedCode {}

    unsafe fn code_func<T>(code: *mut u8, index: u32) -> T {
        let limit = *(code as *mut u32);
        assert!(index < limit);
        let pos = *(code as *mut u32).add(index as usize + 1);
        mem::transmute_copy(&code.add(pos as usize))
    }

    unsafe fn verify_code(code: &LoadedCode) {
        assert_eq!(*(code.get_ref)(), 0);
        assert_eq!((code.cmp_nonzero)(), 0);
        assert_eq!((code.cmp_nonzero_byte)(), 0);
        assert_eq!((code.read_value)(), 0);
        assert_eq!((code.indirected_read)(), 0);
        assert_eq!((code.early_jump)(0, 700), 700);
        assert_eq!((code.early_jump)(250, 700), 350000);
        assert_eq!((code.early_jump_twice)(0xc30c_c30c, 700), 700);
        assert_eq!((code.early_jump_twice)(250, 700), 350000);
        (code.write_value)(7);

        assert_eq!(*(code.get_ref)(), 7);
        assert_eq!((code.cmp_nonzero)(), 1);
        assert_eq!((code.cmp_nonzero_byte)(), 1);
        assert_eq!((code.read_value)(), 7);
        assert_eq!((code.indirected_read)(), 7);
        assert_eq!((code.early_jump)(0, 700), 700);
        assert_eq!((code.early_jump)(250, 700), 350000 - 7);
        assert_eq!((code.early_jump_twice)(0xc30c_c30c, 700), 700);
        assert_eq!((code.early_jump_twice)(250, 700), 350000 - 7);
        (code.write_value)(0);
    }

    fn load_code() -> LoadedCode {
        let data = include_bytes!("x86_64_riprel.bin");
        unsafe {
            let out = VirtualAlloc(
                null_mut(),
                4096,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            assert!(out.is_null() == false);
            ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
            let result = LoadedCode {
                base: out,
                get_ref: code_func(out, 0),
                cmp_nonzero: code_func(out, 1),
                cmp_nonzero_byte: code_func(out, 2),
                read_value: code_func(out, 3),
                write_value: code_func(out, 4),
                indirected_read: code_func(out, 5),
                early_jump: code_func(out, 6),
                early_jump_twice: code_func(out, 7),
                with_stack_frame_entry: code_func(out, 8),
                with_stack_frame_middle: code_func(out, 9),
            };
            verify_code(&result);
            result
        }
    }

    #[test]
    fn patch_get_ref() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            let other = AtomicU32::new(0u32);
            patch.hook_closure_address(GetRef, move |orig| {
                let val = orig();
                *val += 1;
                &other as *const AtomicU32 as *const u32 as *mut u32
            }, code.get_ref as usize - code.base as usize);

            (code.write_value)(999);
            assert_eq!(*(code.get_ref)(), 0);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
            assert_eq!((code.read_value)(), 1000);
            assert_eq!((code.indirected_read)(), 1000);
            *(code.get_ref)() += 5;
            assert_eq!(*(code.get_ref)(), 5);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
            assert_eq!((code.read_value)(), 1002);
            assert_eq!((code.indirected_read)(), 1002);
        }
    }

    #[test]
    fn patch_read_value() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            patch.hook_closure_address(ReadAny, move |orig| {
                orig() ^ 1
            }, code.read_value as usize - code.base as usize);

            (code.write_value)(999);
            assert_eq!(*(code.get_ref)(), 999);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
            assert_eq!((code.read_value)(), 998);
            assert_eq!((code.indirected_read)(), 998);
            *(code.get_ref)() += 5;
            assert_eq!(*(code.get_ref)(), 1004);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
            assert_eq!((code.read_value)(), 1005);
            assert_eq!((code.indirected_read)(), 1005);
        }
    }

    #[test]
    fn patch_read_value2() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            patch.hook_closure_address(ReadAny, move |orig| {
                orig() ^ 1
            }, code.indirected_read as usize - code.base as usize);

            (code.write_value)(999);
            assert_eq!(*(code.get_ref)(), 999);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
            assert_eq!((code.read_value)(), 999);
            assert_eq!((code.indirected_read)(), 998);
            *(code.get_ref)() += 5;
            assert_eq!(*(code.get_ref)(), 1004);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
            assert_eq!((code.read_value)(), 1004);
            assert_eq!((code.indirected_read)(), 1005);
        }
    }

    #[test]
    fn patch_write_value() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            patch.hook_closure_address(Write, move |x, orig| {
                orig(x.wrapping_add(8))
            }, code.write_value as usize - code.base as usize);

            (code.write_value)(248);
            assert_eq!(*(code.get_ref)(), 256);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 0);
            (code.write_value)(u32::MAX);
            assert_eq!(*(code.get_ref)(), 7);
            assert_eq!((code.cmp_nonzero)(), 1);
            assert_eq!((code.cmp_nonzero_byte)(), 1);
        }
    }

    #[test]
    fn patch_cmps() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            patch.hook_closure_address(ReadAny, move |orig| {
                *(code.get_ref)() += 4;
                orig() + 1
            }, code.cmp_nonzero as usize - code.base as usize);
            patch.hook_closure_address(ReadAny, move |orig| {
                *(code.get_ref)() -= 1;
                orig().wrapping_sub(1)
            }, code.cmp_nonzero_byte as usize - code.base as usize);

            (code.write_value)(252);
            assert_eq!((code.cmp_nonzero)(), 2);
            assert_eq!((code.cmp_nonzero_byte)(), 0);
            assert_eq!((code.read_value)(), 255);
            (code.write_value)(253);
            assert_eq!((code.cmp_nonzero)(), 2);
            assert_eq!((code.cmp_nonzero_byte)(), u32::MAX);
            assert_eq!((code.read_value)(), 256);
        }
    }

    #[test]
    fn hook_multiple_times() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            for _ in 0..3 {
                let mut patch = patcher.patch_memory(
                    code.base as *mut _,
                    code.base as *mut _,
                    code.base as usize,
                );
                patch.hook_closure_address(Write, move |x, orig| {
                    orig(x * 2);
                }, code.write_value as usize - code.base as usize);
            }

            (code.write_value)(99);
            assert_eq!(*(code.get_ref)(), 99 * 8);
            assert_eq!((code.read_value)(), 99 * 8);
            assert_eq!((code.cmp_nonzero)(), 1);
        }
    }

    #[test]
    fn early_jump_in_hook_single() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            patch.hook_closure_address(BinaryFunc, move |a, b, orig| {
                orig(a - 1, b - 2)
            }, code.early_jump as usize - code.base as usize);
            (code.write_value)(6);
            assert_eq!((code.early_jump)(4, 4), (4 - 1) * 2 * (4 - 2) - 6);
            assert_eq!((code.early_jump)(7, 7), (7 - 1) * 2 * (7 - 2) - 6);
            assert_eq!((code.early_jump)(1, 2), 2 - 2);
            assert_eq!((code.early_jump)(1, 6), 6 - 2);
        }
    }

    #[test]
    fn early_jump_in_hook_multiple() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            for _ in 0..3 {
                let mut patch = patcher.patch_memory(
                    code.base as *mut _,
                    code.base as *mut _,
                    code.base as usize,
                );
                patch.hook_closure_address(BinaryFunc, move |a, b, orig| {
                    orig(a - 1, b - 2)
                }, code.early_jump as usize - code.base as usize);
            }
            (code.write_value)(6);
            assert_eq!((code.early_jump)(40, 40), (40 - 3) * 2 * (40 - 6) - 6);
            assert_eq!((code.early_jump)(7, 7), (7 - 3) * 2 * (7 - 6) - 6);
            assert_eq!((code.early_jump)(3, 9), 9 - 6);
            assert_eq!((code.early_jump)(3, 6), 6 - 6);
        }
    }

    #[test]
    fn early_jump_twice_in_hook_single() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            let mut patch = patcher.patch_memory(
                code.base as *mut _,
                code.base as *mut _,
                code.base as usize,
            );
            patch.hook_closure_address(BinaryFunc, move |a, b, orig| {
                orig(a - 1, b - 2)
            }, code.early_jump_twice as usize - code.base as usize);
            (code.write_value)(6);
            assert_eq!((code.early_jump_twice)(4, 4), (4 - 1) * 2 * (4 - 2) - 6);
            assert_eq!((code.early_jump_twice)(7, 7), (7 - 1) * 2 * (7 - 2) - 6);
            assert_eq!((code.early_jump_twice)(0xc000_0001, 2), 2 - 2);
            assert_eq!((code.early_jump_twice)(0x8000_0001, 6), 6 - 2);
            assert_eq!(
                (code.early_jump_twice)(0x8000_0000, 6),
                0xffffu32 * 2 * 4 - 6,
            );
        }
    }

    #[test]
    fn early_jump_twice_in_hook_multiple() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            for _ in 0..3 {
                let mut patch = patcher.patch_memory(
                    code.base as *mut _,
                    code.base as *mut _,
                    code.base as usize,
                );
                patch.hook_closure_address(BinaryFunc, move |a, b, orig| {
                    orig(a - 1, b - 2)
                }, code.early_jump_twice as usize - code.base as usize);
            }
            (code.write_value)(6);
            assert_eq!((code.early_jump_twice)(40, 40), (40 - 3) * 2 * (40 - 6) - 6);
            assert_eq!((code.early_jump_twice)(7, 7), (7 - 3) * 2 * (7 - 6) - 6);
            assert_eq!((code.early_jump_twice)(3, 9), 9 - 6);
            assert_eq!((code.early_jump_twice)(3, 6), 6 - 6);
            assert_eq!((code.early_jump_twice)(0xc000_0001, 437), 437 - 6);
            assert_eq!((code.early_jump_twice)(0x8000_0003, 40), 40 - 6);
            assert_eq!(
                (code.early_jump_twice)(0x8000_0001, 80),
                0xfffeu32 * 2 * (80 - 6) - 6,
            );
        }
    }

    // Verify that call hook works regardless of rsp value
    #[test]
    fn call_hook_on_entry() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            {
                let mut patch = patcher.patch_memory(
                    code.base as *mut _,
                    code.base as *mut _,
                    code.base as usize,
                );
                patch.call_hook_closure_address(BinaryFunc, move |a, b, _| {
                    verify_rsp_align();
                    assert_eq!(a, 0x500);
                    assert_eq!(b, 0x900);
                    0
                }, code.with_stack_frame_entry as usize - code.base as usize);
            }
            assert_eq!((code.with_stack_frame_entry)(0x500, 0x900), 0x5900);
        }
    }

    // Verify that call hook works regardless of rsp value, part 2
    #[test]
    fn call_hook_on_middle() {
        unsafe {
            let code = load_code();

            let mut patcher = Patcher::new();
            {
                let mut patch = patcher.patch_memory(
                    code.base as *mut _,
                    code.base as *mut _,
                    code.base as usize,
                );
                patch.call_hook_closure_address(BinaryFunc, move |a, b, _| {
                    verify_rsp_align();
                    assert_eq!(a, 0x100);
                    assert_eq!(b, 0x5900);
                    0
                }, code.with_stack_frame_middle as usize - code.base as usize);
            }
            assert_eq!((code.with_stack_frame_entry)(0x500, 0x900), 0x5900);
        }
    }

    unsafe fn verify_rsp_align() {
        let out = VirtualAlloc(
            null_mut(),
            4096,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        assert!(out.is_null() == false);
        let data = [
            0x48, 0x89, 0xe0, 0xc3, // mov rax, rsp; ret
        ];
        ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
        let func: unsafe extern "C" fn() -> usize = mem::transmute(out);
        let rsp = func();
        // Of course, if the program has made it this far with misaligned rsp,
        // (Likely since the calling code isn't that complex)
        // it'll crash at panicking code most likely
        assert_eq!(rsp & 0xf, 0x8);
    }
}
