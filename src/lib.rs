#![feature(libc, link_args)]
#[link_args = "-static-libgcc"]
extern {}
extern crate libc;
extern crate kernel32;
extern crate winapi;

use PatchHistory::*;
use std::mem;

mod platform;

enum PatchHistory {
    Replace32(*mut u32, u32),
    Replace(*mut u8, Vec<u8>),
}

pub struct PatchManager {
    history: Vec<PatchHistory>,
}

impl PatchManager {
    pub fn new() -> PatchManager {
        PatchManager {
            history: Vec::new(),
        }
    }
    pub unsafe fn patch_exe(&mut self) -> Patch {
        let exe_addr = platform::exe_addr();
        Patch {
            parent: self,
            _protection: platform::MemoryProtection::new(exe_addr),
            diff: 0,
        }
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
    pub unsafe fn replace<Addr:ToPointer>(&mut self, addr: &Addr, data: Vec<u8>) {
        let ptr = addr.ptr().offset(self.diff);
        let mut i = 0;
        for byte in data.iter() {
            *ptr.offset(i) = *byte;
            i += 1;
        }
        self.parent.history.push(Replace(ptr, data));
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
