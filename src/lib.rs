#![feature(libc)]
#![feature(plugin)]
#![plugin(core)]
extern crate libc;
extern crate kernel32;
extern crate winapi;

use PatchHistory::*;
use std::mem;

mod platform;

enum PatchHistory {
    Nop(*mut u8, usize),
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
        let ptr = addr.ptr().offset(self.diff);
        self.parent.history.push(Nop(ptr, len));
        for i in 0..len {
            *ptr.offset(i as isize) = platform::nop();
        }
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
