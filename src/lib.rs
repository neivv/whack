#![feature(libc, link_args, asm)]
#[link_args = "-static-libgcc"]
extern {}
extern crate libc;
extern crate kernel32;
extern crate winapi;

use PatchHistory::*;
use std::{ops, mem};
use std::marker::PhantomData;

mod platform;

enum PatchHistory {
    Replace32(*mut u32, u32),
    Replace(*mut u8, Vec<u8>),
}

pub struct PatchManager {
    history: Vec<PatchHistory>,
    exec_heap: platform::ExecutableHeap,
}

impl PatchManager {
    pub fn new() -> PatchManager {
        PatchManager {
            history: Vec::new(),
            exec_heap: platform::ExecutableHeap::new(),
        }
    }

    pub unsafe fn patch_exe<P: FnMut(Patch)>(&mut self, mut closure: P) {
        let exe_addr = platform::exe_addr();
        let _protection = platform::MemoryProtection::new(exe_addr);
        closure(Patch {
            parent: self,
            base: mem::transmute(exe_addr),
        });
    }

    pub unsafe fn patch_exe_with_base<P: FnMut(PatchWithBase)>(&mut self, base: usize, mut closure: P) {
        self.patch_exe(|patch| {
            closure(PatchWithBase {
                patch: patch,
                expected_base: base,
            });
        });
    }

    pub unsafe fn patch_library<P: FnMut(Patch)>(&mut self, lib: &str, mut closure: P) {
        let lib_addr = platform::library_addr(lib);
        let _protection = platform::MemoryProtection::new(lib_addr);
        closure(Patch {
            parent: self,
            base: mem::transmute(lib_addr),
        });
    }

    pub unsafe fn patch_library_with_base<P: FnMut(PatchWithBase)>(&mut self, lib: &str, base: usize, mut closure: P) {
        self.patch_library(lib, |patch| {
            closure(PatchWithBase {
                patch: patch,
                expected_base: base,
            });
        });
    }

    /// Hackish way to support weird calling conventions that some callbacks may require.
    /// (Or fastcall ._.)
    pub fn callback_hook<Hook>(&mut self, _hook: Hook, target: Hook::Target) -> *const u8
    where Hook: HookableAsmWrap {
        let mut patch = Patch {
            parent: self,
            base: 0,
        };
        unsafe { mem::transmute(patch.make_hook_wrapper::<Hook>(target)) }
    }
}

pub struct Patch<'a> {
    parent: &'a mut PatchManager,
    base: usize,
}

pub struct PatchWithBase<'a> {
    patch: Patch<'a>,
    expected_base: usize
}

impl<'a> Patch<'a> {
    pub unsafe fn hook<Hook>(&mut self, _hook: Hook, target: Hook::Target) where Hook: HookableAsmWrap {
        let data = self.make_hook_wrapper::<Hook>(target);
        let diff = self.base.overflowing_sub(Hook::expected_base()).0;
        let src = Hook::address().overflowing_add(diff).0;
        platform::jump_hook(src, mem::transmute(data));
    }

    unsafe fn make_hook_wrapper<Hook>(&mut self, target: Hook::Target) -> *mut u8 where
        Hook: HookableAsmWrap
    {
        let mut hook_ptr: *mut u8 = mem::transmute(&target);
        let mut code = Hook::get_hook_wrapper();
        let mut code_size = 0;
        while *code != 0xcc { code = code.offset(1); }
        code = code.offset(1);
        let mut hook_pos = code;
        while *hook_pos != 0xcc { hook_pos = hook_pos.offset(1); code_size += 1; }
        let mut code_end = hook_pos;
        while *code_end == 0xcc { code_end = code_end.offset(1); code_size += 1; }
        while *code_end != 0xcc { code_end = code_end.offset(1); code_size += 1; }
        let data = self.alloc_exec(code_size);
        let mut data_pos = data;

        while code != hook_pos {
            *data_pos = *code;
            code = code.offset(1);
            data_pos = data_pos.offset(1);
        }
        while *code == 0xcc {
            *data_pos = *hook_ptr;
            hook_ptr = hook_ptr.offset(1);
            code = code.offset(1);
            data_pos = data_pos.offset(1);
        }
        while code != code_end {
            *data_pos = *code;
            code = code.offset(1);
            data_pos = data_pos.offset(1);
        }
        data
    }

    pub unsafe fn call_hook<Hook>(&mut self, _hook: Hook, target: Hook::Target) where Hook: HookableAsmWrap {
        let data = self.make_hook_wrapper::<Hook>(target);
        let diff = self.base.overflowing_sub(Hook::expected_base()).0;
        let src = Hook::address().overflowing_add(diff).0;
        platform::call_hook(src, mem::transmute(data), &mut self.parent.exec_heap);
    }

    fn alloc_exec(&mut self, size: usize) -> *mut u8 {
        self.parent.exec_heap.allocate(size)
    }
}

impl<'a> PatchWithBase<'a> {
    fn current_base<Addr: ToPointer>(&self, addr: Addr) -> *mut u8 {
        let diff = self.patch.base.overflowing_sub(self.expected_base).0;
        unsafe { mem::transmute(mem::transmute::<_, usize>(addr.ptr()).overflowing_add(diff).0) }
    }

    pub unsafe fn nop<Addr: ToPointer>(&mut self, addr: Addr, len: usize) {
        self.replace(addr, vec![platform::nop(); len])
    }

    pub unsafe fn replace_u32<Addr: ToPointer>(&mut self, addr: Addr, val: u32) {
        let ptr: *mut u32 = mem::transmute(self.current_base(addr));
        self.patch.parent.history.push(Replace32(ptr, val));
        *ptr = val;
    }

    pub unsafe fn replace<Addr: ToPointer>(&mut self, addr: Addr, data: Vec<u8>) {
        let ptr = self.current_base(addr);
        let mut i = 0;
        for byte in data.iter() {
            *ptr.offset(i) = *byte;
            i += 1;
        }
        self.patch.parent.history.push(Replace(ptr, data));
    }
}

impl<'a> ops::Deref for PatchWithBase<'a> {
    type Target = Patch<'a>;
    fn deref(&self) -> &Patch<'a> {
        &self.patch
    }
}

impl<'a> ops::DerefMut for PatchWithBase<'a> {
    fn deref_mut(&mut self) -> &mut Patch<'a> {
        &mut self.patch
    }
}

pub trait ToPointer {
    fn ptr(&self) -> *mut u8;
}

impl ToPointer for usize {
    fn ptr(&self) -> *mut u8 {
        unsafe { mem::transmute(*self) }
    }
}

impl<T> ToPointer for *mut T {
    fn ptr(&self) -> *mut u8 {
        unsafe { mem::transmute::<*mut T, *mut u8>(*self) }
    }
}

/// Redirects stderr to file.
/// Accepts only ascii strings for filename to avoid unicode dependency.
pub unsafe fn redirect_stderr(filename: &str) -> bool {
    platform::redirect_stderr(filename)
}

pub trait HookableAsmWrap {
    type Target;
    unsafe fn get_hook_wrapper() -> *const u8;
    fn address() -> usize;
    fn expected_base() -> usize;
}

pub struct Variable<T> {
    pub address: usize,
    pub phantom: PhantomData<T>,
}

unsafe impl<T> Sync for Variable<T> { }

impl<T> Variable<T> {
    pub fn new(addr: usize) -> Variable<T> {
        Variable {
            address: addr,
            phantom: PhantomData,
        }
    }
    pub unsafe fn ptr(&self) -> *const T {
        mem::transmute(self.address)
    }
    pub unsafe fn mut_ptr(&self) -> *mut T {
        mem::transmute(self.address)
    }
}

impl<T> ops::Deref for Variable<T> {
    type Target = T;
    fn deref<'a>(&'a self) -> &'a T {
        unsafe { mem::transmute(self.address) }
    }
}

impl<T> ops::DerefMut for Variable<T> {
    fn deref_mut<'a>(&'a mut self) -> &'a mut T {
        unsafe { mem::transmute(self.address) }
    }
}
