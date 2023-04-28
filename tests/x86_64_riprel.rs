#[macro_use]
#[cfg(target_arch = "x86_64")]
extern crate whack;

#[cfg(target_arch = "x86_64")]
mod test {
    use std::mem;
    use std::ptr::{self, null_mut};
    use std::sync::atomic::{AtomicU32};

    use winapi::um::memoryapi::{VirtualAlloc};
    use winapi::um::winnt;

    use whack::Patcher;

    whack_hooks!(0,
        0 => GetRef() -> *mut u32;
        0 => ReadAny() -> u32;
        0 => Write(u32);
    );

    #[derive(Copy, Clone)]
    struct LoadedCode {
        base: *mut u8,
        get_ref: unsafe extern fn() -> *mut u32,
        cmp_nonzero: unsafe extern fn() -> u32,
        cmp_nonzero_byte: unsafe extern fn() -> u32,
        read_value: unsafe extern fn() -> u32,
        write_value: unsafe extern fn(u32),
        indirected_read: unsafe extern fn() -> u32,
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
        (code.write_value)(7);

        assert_eq!(*(code.get_ref)(), 7);
        assert_eq!((code.cmp_nonzero)(), 1);
        assert_eq!((code.cmp_nonzero_byte)(), 1);
        assert_eq!((code.read_value)(), 7);
        assert_eq!((code.indirected_read)(), 7);
        (code.write_value)(0);
    }

    fn load_code() -> LoadedCode {
        let data = include_bytes!("x86_64_riprel.bin");
        unsafe {
            let out = VirtualAlloc(
                null_mut(),
                4096,
                winnt::MEM_RESERVE | winnt::MEM_COMMIT,
                winnt::PAGE_EXECUTE_READWRITE,
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
}
