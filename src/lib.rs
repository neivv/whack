#![feature(libc, link_args, wrapping, str_utf16, asm)]
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
    pub unsafe fn patch_exe<P: FnMut(&mut Patch)>(&mut self, mut closure: P) {
        let exe_addr = platform::exe_addr();
        let mut patch = Patch {
            parent: self,
            _protection: platform::MemoryProtection::new(exe_addr),
            diff: 0,
        };
        closure(&mut patch);
    }
}

pub struct Patch<'a> {
    parent: &'a mut PatchManager,
    _protection: platform::MemoryProtection,
    diff: isize,
}

impl<'a> Patch<'a> {
    pub unsafe fn nop<Addr: ToPointer>(&mut self, addr: &Addr, len: usize) {
        self.replace(addr, vec![platform::nop(); len])
    }
    pub unsafe fn replace_u32<Addr: ToPointer>(&mut self, addr: &Addr, val: u32) {
        let ptr: *mut u32 = mem::transmute(addr.ptr().offset(self.diff));
        self.parent.history.push(Replace32(ptr, val));
        *ptr = val;
    }
    pub unsafe fn replace<Addr: ToPointer>(&mut self, addr: &Addr, data: Vec<u8>) {
        let ptr = addr.ptr().offset(self.diff);
        let mut i = 0;
        for byte in data.iter() {
            *ptr.offset(i) = *byte;
            i += 1;
        }
        self.parent.history.push(Replace(ptr, data));
    }

    pub unsafe fn hook<Hook>(&mut self, _hook: Hook, target: Hook::Target) where Hook: HookableAsmWrap {
        let data = self.make_hook_wrapper::<Hook>(target);
        platform::jump_hook(Hook::address(), mem::transmute(data));
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
        platform::call_hook(Hook::address(), mem::transmute(data), &mut self.parent.exec_heap);
    }

    fn alloc_exec(&mut self, size: usize) -> *mut u8 {
        self.parent.exec_heap.allocate(size)
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

/// Redirects stderr to file.
/// Accepts only ascii strings for filename to avoid unicode dependency.
pub unsafe fn redirect_stderr(filename: &str) -> bool {
    platform::redirect_stderr(filename)
}

pub trait HookableAsmWrap {
    type Target;
    unsafe fn get_hook_wrapper() -> *const u8;
    fn address() -> usize;
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
