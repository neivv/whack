use std::mem;
use std::ptr::{NonNull};

use winapi::um::memoryapi::{VirtualAlloc, VirtualQuery};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::winnt::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

pub struct NearModuleAllocator {
    pos: *mut u8,
    page_end: *mut u8,
    allocation_granularity: usize,
}

unsafe impl Send for NearModuleAllocator {}
unsafe impl Sync for NearModuleAllocator {}

impl NearModuleAllocator {
    pub fn new(module: *const u8) -> NearModuleAllocator {
        unsafe {
            let mut info: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut info);
            // Start searching for space below the module if module is at offset big enough,
            // or above otherwise
            let pos = if module as usize > 0x1_0000_0000 {
                ((module as usize) - 0x4000_0000) as *mut u8
            } else {
                ((module as usize) + 0x0100_0000) as *mut u8
            };
            NearModuleAllocator {
                pos,
                page_end: pos,
                allocation_granularity: info.dwAllocationGranularity as usize,
            }
        }
    }

    fn capacity(&self) -> usize {
        self.page_end as usize - self.pos as usize
    }

    #[must_use]
    fn alloc_page(&mut self, min_size: usize) -> bool {
        unsafe {
            let size = align_size(min_size, self.allocation_granularity);
            let mut pos = self.page_end;
            let mut buf: MEMORY_BASIC_INFORMATION = mem::zeroed();
            let buf_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();
            for _ in 0..10000 {
                let start = align_size(pos as usize, self.allocation_granularity);
                pos = start as *mut u8;
                let ok = VirtualQuery(pos as *const _, &mut buf, buf_size);
                let end = (pos as usize).wrapping_add(buf.RegionSize) &
                    !self.allocation_granularity.wrapping_sub(1);
                if ok == 0 {
                    return false;
                }
                if buf.State == MEM_FREE && end.saturating_sub(start) >= size {
                    let ok = VirtualAlloc(
                        start as *mut _,
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    let start = start as *mut u8;
                    if !ok.is_null() {
                        assert_eq!(ok as usize, start as usize);
                        self.pos = start;
                        self.page_end = start.add(size);
                        return true;
                    }
                }
                pos = pos.add(buf.RegionSize);
            }
            false
        }
    }

    pub fn allocate(&mut self, size: usize) -> *mut u8 {
        let alloc_size = align_size(size, 16);
        if self.capacity() < size {
            if !self.alloc_page(alloc_size) {
                panic!("Failed to allocate");
            }
        }
        unsafe {
            let val = self.pos;
            self.pos = val.add(alloc_size);
            val
        }
    }

    pub fn allocate_near(
        &mut self,
        range: (*const u8, *const u8),
        size: usize,
    ) -> Option<NonNull<u8>> {
        let alloc_size = align_size(size, 16);
        if self.capacity() < size {
            if !self.alloc_page(alloc_size) {
                return None;
            }
        }
        if is_near(self.pos, range, alloc_size) {
            unsafe {
                let val = self.pos;
                self.pos = val.add(alloc_size);
                Some(NonNull::new_unchecked(val))
            }
        } else {
            None
        }
    }
}

fn is_near(ptr: *mut u8, (start, end): (*const u8, *const u8), len: usize) -> bool {
    // Not trying to handle the exact 0x8000_0000 boundary, that'll
    // just end up being off-by-one bug.
    if len > 0x7000_0000 {
        return false;
    }
    let min = (end as usize).wrapping_sub(0x7000_0000);
    let max = (start as usize).wrapping_add(0x7000_0000 - len);
    (ptr as usize).wrapping_sub(min) < max.wrapping_sub(min)
}

#[inline]
pub const fn align_size(val: usize, align: usize) -> usize {
    (val.wrapping_sub(1) | align.wrapping_sub(1)).wrapping_add(1)
}
