use std::ptr;

// Unused in x86_64 atm
#[cfg(target_arch = "x86")]
pub unsafe fn read_unaligned<T>(from: *mut u8) -> T {
    ptr::read_unaligned(from as *mut T as *const T)
}

pub unsafe fn write_unaligned<T>(to: *mut u8, val: T) {
    ptr::write_unaligned(to as *mut T, val)
}

#[inline]
pub fn align(val: usize, to: usize) -> usize {
    let mask = to.wrapping_sub(1);
    assert!(mask & to == 0);
    (val.wrapping_sub(1) | mask).wrapping_add(1)
}

pub trait VecExt {
    fn write_u32_le(&mut self, value: u32);
    #[cfg(target_arch = "x86_64")]
    fn write_u64_le(&mut self, value: u64);
}

impl VecExt for Vec<u8> {
    #[inline]
    fn write_u32_le(&mut self, value: u32) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    #[inline]
    #[cfg(target_arch = "x86_64")]
    fn write_u64_le(&mut self, value: u64) {
        self.extend_from_slice(&value.to_le_bytes());
    }
}

#[test]
fn test_align() {
    assert_eq!(align(0, 4), 0);
    assert_eq!(align(1, 4), 4);
    assert_eq!(align(2, 4), 4);
    assert_eq!(align(3, 4), 4);
    assert_eq!(align(4, 4), 4);
    assert_eq!(align(5, 4), 8);
    assert_eq!(align(0, 8), 0);
    assert_eq!(align(1, 8), 8);
    assert_eq!(align(7, 8), 8);
    assert_eq!(align(8, 8), 8);
    assert_eq!(align(9, 8), 16);
}
