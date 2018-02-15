
#[cfg(target_arch = "x86")]
mod x86 {
    extern crate byteorder;
    extern crate whack;

    use std::fs::File;
    use std::io::Read;
    use std::mem;

    use x86::byteorder::{ReadBytesExt, LE};
    use x86::whack::*;

    whack_hook_decls!(
        InlineDecl(u32, u32, *mut u32);
    );

    #[test]
    fn inline_hook() {
        unsafe {
            let patcher = Patcher::new();
            let mut active = patcher.lock().unwrap();
            let (code, entry, exit, inline_parent_entry) = read_code();
            let mem = {
                let mut p = active.patch_exe(0);
                p.exec_alloc(code.len())
            };
            mem.copy_from_slice(&code);
            let func: extern fn(u32, u32, *mut u32) -> u32 = mem::transmute(mem.as_ptr());
            let mut result = vec![!0; 40];
            let val = func(1, 2, result.as_mut_ptr());
            // The func should store ((((a1 + a2) * 2) ^ 0x50) * 2) - 0x777 to result[0],
            // whether the last addition overflowed or not to result[1],
            // and return a2 + 6
            assert_eq!(result[0], ((6u32 ^ 0x50) * 2).wrapping_sub(0x777));
            assert_eq!(result[1], 1);
            for &x in &result[2..] {
                assert_eq!(x, !0);
            }
            assert_eq!(val, 8);

            let inline = InlineHook {
                entry,
                exit,
                inline_parent_entry,
                args: vec![
                    Arg::Register(0),
                    Arg::Esp(0x2c),
                    Arg::Register(1),
                ],
            };

            let hook = {
                let mut active_patcher = active.patch_memory(
                    mem.as_ptr() as *mut _,
                    mem.as_ptr() as *mut _,
                    !0,
                );
                active_patcher.inline_hook(
                    InlineDecl,
                    &inline,
                    |a1: u32, a2, out: *mut u32, orig: &Fn(_, _, _)| {
                        assert_eq!(a1, a2);
                        orig(a1, 4, out);
                        assert_eq!(*out, (a1 + 4).wrapping_sub(0x777));
                        let mut out2 = vec![1, 2];
                        orig(a1, 9, out2.as_mut_ptr());
                        assert_eq!(out2[0], (a1 + 9).wrapping_sub(0x777));
                        assert_eq!(*out, (a1 + 4).wrapping_sub(0x777));
                        *out = a1 + a2 + 555;
                        *out.offset(1) += 2;
                    },
                );
                active_patcher.apply()
            };
            let val = func(1, 2, result.as_mut_ptr());
            assert_eq!(result[0], ((6 ^ 0x50) * 2) + 555);
            assert_eq!(result[1], 3);
            for &x in &result[2..] {
                assert_eq!(x, !0);
            }
            assert_eq!(val, 8);
            {
                active.disable_patch(&hook);
            }
            let val = func(1, 2, result.as_mut_ptr());
            assert_eq!(result[0], ((6u32 ^ 0x50) * 2).wrapping_sub(0x777));
            assert_eq!(result[1], 1);
            for &x in &result[2..] {
                assert_eq!(x, !0);
            }
            assert_eq!(val, 8);
        }
    }

    fn read_code() -> (Vec<u8>, usize, usize, usize) {
        let mut file = File::open("tests/inline_hook_x86.bin").unwrap();
        let hook_entry = file.read_u32::<LE>().unwrap() as usize;
        let hook_exit = file.read_u32::<LE>().unwrap() as usize;
        let func = file.read_u32::<LE>().unwrap() as usize;
        let mut code = Vec::new();
        file.read_to_end(&mut code).unwrap();
        (code, hook_entry, hook_exit, func)
    }
}
