#![allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::r3::mod3;

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn swap(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return swap_avx2(x, y, n, mask);
    }
    #[allow(unreachable_code)]
    swap_scalar(x, y, n, mask);
}

#[allow(clippy::cast_possible_truncation)]
fn swap_scalar(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
    let c = mask as i8;
    for i in 0..n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

/// 32 i8 elements per SIMD iteration.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[target_feature(enable = "avx2")]
unsafe fn swap_avx2(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
    use core::arch::x86_64::*;
    let cv = _mm256_set1_epi8(mask as i8);
    let mut i = 0usize;
    while i + 32 <= n {
        let xv = _mm256_loadu_si256(x.as_ptr().add(i) as *const __m256i);
        let yv = _mm256_loadu_si256(y.as_ptr().add(i) as *const __m256i);
        let t = _mm256_and_si256(cv, _mm256_xor_si256(xv, yv));
        _mm256_storeu_si256(
            x.as_mut_ptr().add(i) as *mut __m256i,
            _mm256_xor_si256(xv, t),
        );
        _mm256_storeu_si256(
            y.as_mut_ptr().add(i) as *mut __m256i,
            _mm256_xor_si256(yv, t),
        );
        i += 32;
    }
    let c = mask as i8;
    while i < n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
        i += 1;
    }
}

#[inline(always)]
pub fn product(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return product_avx2(z, n, x, c);
    }
    #[allow(unreachable_code)]
    product_scalar(z, n, x, c);
}

fn product_scalar(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    for i in 0..n {
        z[i] = mod3::product(x[i], c);
    }
}

/// For c in {-1, 0, 1}: _mm256_sign_epi8(x, c) computes x * c.
/// Processes 32 elements per iteration.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[target_feature(enable = "avx2")]
unsafe fn product_avx2(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    use core::arch::x86_64::*;
    let cv = _mm256_set1_epi8(c);
    let mut i = 0usize;
    while i + 32 <= n {
        let xv = _mm256_loadu_si256(x.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(
            z.as_mut_ptr().add(i) as *mut __m256i,
            _mm256_sign_epi8(xv, cv),
        );
        i += 32;
    }
    while i < n {
        z[i] = mod3::product(x[i], c);
        i += 1;
    }
}

/// Fused minus_product and shift: z[i+1] = freeze(z[i] - y[i]*c), z[0] = 0.
/// Processes backward to avoid overwrite conflicts, eliminating a separate memmove.
#[inline(always)]
pub fn minus_product_shift(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return minus_product_shift_avx2(z, n, y, c);
    }
    #[allow(unreachable_code)]
    minus_product_shift_scalar(z, n, y, c);
}

fn minus_product_shift_scalar(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    for i in (0..n - 1).rev() {
        z[i + 1] = mod3::minus_product(z[i], y[i], c);
    }
    z[0] = 0;
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_avx2(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    use core::arch::x86_64::*;
    let cv = _mm256_set1_epi8(c);
    let neg2 = _mm256_set1_epi8(-2);
    let pos2 = _mm256_set1_epi8(2);
    let three = _mm256_set1_epi8(3);

    let mut j = (n - 2) as isize;

    // Process 32 i8 elements at a time, backward
    while j >= 31 {
        let start = (j - 31) as usize;
        let zv = _mm256_loadu_si256(z.as_ptr().add(start) as *const __m256i);
        let yv = _mm256_loadu_si256(y.as_ptr().add(start) as *const __m256i);
        let yc = _mm256_sign_epi8(yv, cv);
        let r = _mm256_sub_epi8(zv, yc);
        // Mod-3 fixup: r is in [-2, 2]
        let add = _mm256_and_si256(three, _mm256_cmpeq_epi8(r, neg2));
        let sub = _mm256_and_si256(three, _mm256_cmpeq_epi8(r, pos2));
        let r = _mm256_add_epi8(_mm256_sub_epi8(r, sub), add);
        // Store at offset +1 (the shift)
        _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, r);
        j -= 32;
    }

    // Scalar remainder
    while j >= 0 {
        z[(j + 1) as usize] = mod3::minus_product(z[j as usize], y[j as usize], c);
        j -= 1;
    }
    z[0] = 0;
}
