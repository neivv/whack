#[no_mangle]
pub extern "C" fn test_func(input: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
    (input * 22 + 115) / 9 + e * b.wrapping_sub((9u32.wrapping_mul(b.wrapping_sub(c).wrapping_sub(d) ^ d)) / (12))
}
