#![allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::rq::modq;
#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
use crate::rq::montgomery;

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn swap(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return swap_avx2(x, y, n, mask);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return swap_neon(x, y, n, mask);
    }
    #[allow(unreachable_code)]
    swap_scalar(x, y, n, mask);
}

#[allow(clippy::cast_possible_truncation)]
fn swap_scalar(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    let c = mask as i16;
    for i in 0..n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn swap_avx2(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    use core::arch::x86_64::*;
    let cv = _mm256_set1_epi16(mask as i16);
    let mut i = 0usize;
    while i + 16 <= n {
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
        i += 16;
    }
    let c = mask as i16;
    while i < n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
        i += 1;
    }
}

#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn swap_neon(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    unsafe {
        use core::arch::aarch64::*;
        let cv = vdupq_n_s16(mask as i16);
        let mut i = 0usize;
        while i + 8 <= n {
            let xv = vld1q_s16(x.as_ptr().add(i));
            let yv = vld1q_s16(y.as_ptr().add(i));
            let t = vandq_s16(cv, veorq_s16(xv, yv));
            vst1q_s16(x.as_mut_ptr().add(i), veorq_s16(xv, t));
            vst1q_s16(y.as_mut_ptr().add(i), veorq_s16(yv, t));
            i += 8;
        }
        let c = mask as i16;
        while i < n {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
            i += 1;
        }
    }
}

#[inline(always)]
pub fn product(z: &mut [i16], n: usize, x: &[i16], c: i16) {
    for i in 0..n {
        z[i] = modq::product(x[i], c);
    }
}

/// Fused minus_product and shift: z[i+1] = freeze(z[i] - y[i]*c), z[0] = 0.
/// Processes backward to avoid overwrite conflicts, eliminating a separate memmove.
#[inline(always)]
pub fn minus_product_shift(z: &mut [i16], n: usize, y: &[i16], c: i16) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return minus_product_shift_avx2(z, n, y, c);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return minus_product_shift_neon(z, n, y, c);
    }
    #[allow(unreachable_code)]
    minus_product_shift_scalar(z, n, y, c);
}

fn minus_product_shift_scalar(z: &mut [i16], n: usize, y: &[i16], c: i16) {
    for i in (0..n - 1).rev() {
        z[i + 1] = modq::minus_product(z[i], y[i], c);
    }
    z[0] = 0;
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_avx2(z: &mut [i16], n: usize, y: &[i16], c: i16) {
    use core::arch::x86_64::*;
    let qv = _mm256_set1_epi32(crate::Q as i32);
    let k228 = _mm256_set1_epi32(228);
    let k58470 = _mm256_set1_epi32(58470);
    let k134m = _mm256_set1_epi32(134_217_728);
    let cv = _mm256_set1_epi32(c as i32);

    let mut j = (n - 2) as isize;

    // Process 16 at a time (two 8-wide batches for ILP), backward
    while j >= 15 {
        let start = (j - 15) as usize;

        // Batch 0: elements start..start+8
        let zv0 = _mm256_cvtepi16_epi32(_mm_loadu_si128(z.as_ptr().add(start) as *const __m128i));
        let yv0 = _mm256_cvtepi16_epi32(_mm_loadu_si128(y.as_ptr().add(start) as *const __m128i));
        let a0 = _mm256_sub_epi32(zv0, _mm256_mullo_epi32(yv0, cv));

        // Batch 1: elements start+8..start+16
        let zv1 =
            _mm256_cvtepi16_epi32(_mm_loadu_si128(z.as_ptr().add(start + 8) as *const __m128i));
        let yv1 =
            _mm256_cvtepi16_epi32(_mm_loadu_si128(y.as_ptr().add(start + 8) as *const __m128i));
        let a1 = _mm256_sub_epi32(zv1, _mm256_mullo_epi32(yv1, cv));

        // Barrett freeze batch 0
        let t0 = _mm256_srai_epi32(_mm256_mullo_epi32(a0, k228), 20);
        let b0 = _mm256_sub_epi32(a0, _mm256_mullo_epi32(t0, qv));
        let t0 = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b0, k58470), k134m), 28);
        let r0 = _mm256_sub_epi32(b0, _mm256_mullo_epi32(t0, qv));

        // Barrett freeze batch 1
        let t1 = _mm256_srai_epi32(_mm256_mullo_epi32(a1, k228), 20);
        let b1 = _mm256_sub_epi32(a1, _mm256_mullo_epi32(t1, qv));
        let t1 = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b1, k58470), k134m), 28);
        let r1 = _mm256_sub_epi32(b1, _mm256_mullo_epi32(t1, qv));

        // Pack 8+8 i32 -> 16 i16 and store at offset +1 (the shift)
        let packed = _mm256_permute4x64_epi64(_mm256_packs_epi32(r0, r1), 0xD8);
        _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, packed);
        j -= 16;
    }

    // Process remaining 8 at a time
    while j >= 7 {
        let start = (j - 7) as usize;
        let zv = _mm256_cvtepi16_epi32(_mm_loadu_si128(z.as_ptr().add(start) as *const __m128i));
        let yv = _mm256_cvtepi16_epi32(_mm_loadu_si128(y.as_ptr().add(start) as *const __m128i));
        let a = _mm256_sub_epi32(zv, _mm256_mullo_epi32(yv, cv));

        let t = _mm256_srai_epi32(_mm256_mullo_epi32(a, k228), 20);
        let b = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, qv));
        let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b, k58470), k134m), 28);
        let r = _mm256_sub_epi32(b, _mm256_mullo_epi32(t, qv));

        let lo = _mm256_castsi256_si128(r);
        let hi = _mm256_extracti128_si256(r, 1);
        _mm_storeu_si128(
            z.as_mut_ptr().add(start + 1) as *mut __m128i,
            _mm_packs_epi32(lo, hi),
        );
        j -= 8;
    }

    // Scalar remainder
    while j >= 0 {
        z[(j + 1) as usize] = modq::minus_product(z[j as usize], y[j as usize], c);
        j -= 1;
    }
    z[0] = 0;
}

/// NEON Barrett minus_product_shift: 4 i32 elements at a time (128-bit), backward.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn minus_product_shift_neon(z: &mut [i16], n: usize, y: &[i16], c: i16) {
    unsafe {
        use core::arch::aarch64::*;
        let qv = vdupq_n_s32(crate::Q as i32);
        let k228 = vdupq_n_s32(228);
        let k58470 = vdupq_n_s32(58470);
        let k134m = vdupq_n_s32(134_217_728);
        let cv = vdupq_n_s32(c as i32);

        let mut j = (n - 2) as isize;

        // Process 8 at a time (two 4-wide batches), backward
        while j >= 7 {
            let start = (j - 7) as usize;

            // Batch 0: elements start..start+4
            let zv0 = vmovl_s16(vld1_s16(z.as_ptr().add(start)));
            let yv0 = vmovl_s16(vld1_s16(y.as_ptr().add(start)));
            let a0 = vsubq_s32(zv0, vmulq_s32(yv0, cv));

            // Batch 1: elements start+4..start+8
            let zv1 = vmovl_s16(vld1_s16(z.as_ptr().add(start + 4)));
            let yv1 = vmovl_s16(vld1_s16(y.as_ptr().add(start + 4)));
            let a1 = vsubq_s32(zv1, vmulq_s32(yv1, cv));

            // Barrett freeze batch 0
            let t0 = vshrq_n_s32(vmulq_s32(a0, k228), 20);
            let b0 = vsubq_s32(a0, vmulq_s32(t0, qv));
            let t0 = vshrq_n_s32(vaddq_s32(vmulq_s32(b0, k58470), k134m), 28);
            let r0 = vsubq_s32(b0, vmulq_s32(t0, qv));

            // Barrett freeze batch 1
            let t1 = vshrq_n_s32(vmulq_s32(a1, k228), 20);
            let b1 = vsubq_s32(a1, vmulq_s32(t1, qv));
            let t1 = vshrq_n_s32(vaddq_s32(vmulq_s32(b1, k58470), k134m), 28);
            let r1 = vsubq_s32(b1, vmulq_s32(t1, qv));

            // Pack 4+4 i32 -> 8 i16 (naturally ordered, no permute needed)
            let packed = vcombine_s16(vmovn_s32(r0), vmovn_s32(r1));
            vst1q_s16(z.as_mut_ptr().add(start + 1), packed);
            j -= 8;
        }

        // Process 4 at a time
        while j >= 3 {
            let start = (j - 3) as usize;
            let zv = vmovl_s16(vld1_s16(z.as_ptr().add(start)));
            let yv = vmovl_s16(vld1_s16(y.as_ptr().add(start)));
            let a = vsubq_s32(zv, vmulq_s32(yv, cv));

            let t = vshrq_n_s32(vmulq_s32(a, k228), 20);
            let b = vsubq_s32(a, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b, k58470), k134m), 28);
            let r = vsubq_s32(b, vmulq_s32(t, qv));

            vst1_s16(z.as_mut_ptr().add(start + 1), vmovn_s32(r));
            j -= 4;
        }

        // Scalar remainder
        while j >= 0 {
            z[(j + 1) as usize] = modq::minus_product(z[j as usize], y[j as usize], c);
            j -= 1;
        }
        z[0] = 0;
    }
}

/// Fused Montgomery minus_product and shift: z[i+1] = reduce(z[i] - montmul(y[i], c_mont)), z[0] = 0.
/// Processes backward to avoid overwrite conflicts, eliminating a separate memmove.
#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
#[inline(always)]
pub fn minus_product_shift_mont(z: &mut [i16], n: usize, y: &[i16], c_mont: i16) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return minus_product_shift_mont_avx2(z, n, y, c_mont);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return minus_product_shift_mont_neon(z, n, y, c_mont);
    }
    #[allow(unreachable_code)]
    minus_product_shift_mont_scalar(z, n, y, c_mont);
}

#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
fn minus_product_shift_mont_scalar(z: &mut [i16], n: usize, y: &[i16], c_mont: i16) {
    let qinv = montgomery::QINV_4591 as i32;
    let q = montgomery::Q4591 as i32;
    for i in (0..n - 1).rev() {
        let t = y[i] as i32 * c_mont as i32;
        let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
        let prod = ((t - (u as i32) * q) >> 16) as i16;
        let diff = z[i] as i32 - prod as i32;
        z[i + 1] = modq::freeze(diff);
    }
    z[0] = 0;
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_mont_avx2(z: &mut [i16], n: usize, y: &[i16], c_mont: i16) {
    use core::arch::x86_64::*;

    let qinv_vec = _mm256_set1_epi16(montgomery::QINV_4591);
    let q_vec = _mm256_set1_epi16(montgomery::Q4591 as i16);
    let qm1_vec = _mm256_set1_epi16(montgomery::Q4591 as i16 - 1);
    let neg_q_vec = _mm256_set1_epi16(-(montgomery::Q4591 as i16));
    let c_vec = _mm256_set1_epi16(c_mont);

    let mut j = (n - 2) as isize;

    // Process 16 i16 at a time, backward
    while j >= 15 {
        let start = (j - 15) as usize;
        let z_v = _mm256_loadu_si256(z.as_ptr().add(start) as *const __m256i);
        let y_v = _mm256_loadu_si256(y.as_ptr().add(start) as *const __m256i);

        // Montgomery multiply: prod = y * c_mont * R^{-1} mod q
        let t_lo = _mm256_mullo_epi16(y_v, c_vec);
        let t_hi = _mm256_mulhi_epi16(y_v, c_vec);
        let u = _mm256_mullo_epi16(t_lo, qinv_vec);
        let prod = _mm256_sub_epi16(t_hi, _mm256_mulhi_epi16(u, q_vec));

        // Subtract: result = z - prod
        let result = _mm256_sub_epi16(z_v, prod);

        // Reduce to (-q, q)
        let mask_hi = _mm256_cmpgt_epi16(result, qm1_vec);
        let result = _mm256_sub_epi16(result, _mm256_and_si256(mask_hi, q_vec));
        let mask_lo = _mm256_cmpgt_epi16(neg_q_vec, result);
        let result = _mm256_add_epi16(result, _mm256_and_si256(mask_lo, q_vec));

        // Store at offset +1 (the shift)
        _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, result);
        j -= 16;
    }

    // Scalar remainder
    let qinv = montgomery::QINV_4591 as i32;
    let q32 = montgomery::Q4591 as i32;
    while j >= 0 {
        let idx = j as usize;
        let t = y[idx] as i32 * c_mont as i32;
        let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
        let prod = ((t - (u as i32) * q32) >> 16) as i16;
        let diff = z[idx] as i32 - prod as i32;
        z[idx + 1] = modq::freeze(diff);
        j -= 1;
    }
    z[0] = 0;
}

/// NEON Montgomery minus_product_shift: 8 i16 elements at a time, backward.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn minus_product_shift_mont_neon(z: &mut [i16], n: usize, y: &[i16], c_mont: i16) {
    unsafe {
        use core::arch::aarch64::*;

        let qinv_vec = vdupq_n_s16(montgomery::QINV_4591);
        let q_vec = vdupq_n_s16(montgomery::Q4591 as i16);
        let qm1_vec = vdupq_n_s16(montgomery::Q4591 as i16 - 1);
        let neg_q_vec = vnegq_s16(q_vec);
        let c_vec = vdupq_n_s16(c_mont);

        let mut j = (n - 2) as isize;

        // Process 8 i16 at a time, backward
        while j >= 7 {
            let start = (j - 7) as usize;
            let z_v = vld1q_s16(z.as_ptr().add(start));
            let y_v = vld1q_s16(y.as_ptr().add(start));

            // Montgomery multiply: prod = y * c_mont * R^{-1} mod q
            let prod = montgomery::montmul_x8(y_v, c_vec, qinv_vec, q_vec);

            // Subtract: result = z - prod
            let result = vsubq_s16(z_v, prod);

            // Reduce to (-q, q)
            let mask_hi = vcgtq_s16(result, qm1_vec);
            let result = vsubq_s16(result, vandq_s16(vreinterpretq_s16_u16(mask_hi), q_vec));
            let mask_lo = vcgtq_s16(neg_q_vec, result);
            let result = vaddq_s16(result, vandq_s16(vreinterpretq_s16_u16(mask_lo), q_vec));

            // Store at offset +1 (the shift)
            vst1q_s16(z.as_mut_ptr().add(start + 1), result);
            j -= 8;
        }

        // Scalar remainder
        let qinv = montgomery::QINV_4591 as i32;
        let q32 = montgomery::Q4591 as i32;
        while j >= 0 {
            let idx = j as usize;
            let t = y[idx] as i32 * c_mont as i32;
            let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
            let prod = ((t - (u as i32) * q32) >> 16) as i16;
            let diff = z[idx] as i32 - prod as i32;
            z[idx + 1] = modq::freeze(diff);
            j -= 1;
        }
        z[0] = 0;
    }
}

/// Final product in Montgomery domain: z[i] = montmul(x[i], c_std) for i in 0..n.
/// montmul(x_mont, c_std) = x * c (standard form result).
#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
#[inline(always)]
pub fn product_from_mont(z: &mut [i16], n: usize, x: &[i16], c_std: i16) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return product_from_mont_avx2(z, n, x, c_std);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return product_from_mont_neon(z, n, x, c_std);
    }
    #[allow(unreachable_code)]
    product_from_mont_scalar(z, n, x, c_std);
}

#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
fn product_from_mont_scalar(z: &mut [i16], n: usize, x: &[i16], c_std: i16) {
    let qinv = montgomery::QINV_4591 as i32;
    let q = montgomery::Q4591 as i32;
    for i in 0..n {
        let t = x[i] as i32 * c_std as i32;
        let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
        z[i] = ((t - (u as i32) * q) >> 16) as i16;
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn product_from_mont_avx2(z: &mut [i16], n: usize, x: &[i16], c_std: i16) {
    use core::arch::x86_64::*;

    let qinv_vec = _mm256_set1_epi16(montgomery::QINV_4591);
    let q_vec = _mm256_set1_epi16(montgomery::Q4591 as i16);
    let c_vec = _mm256_set1_epi16(c_std);

    let mut i = 0usize;
    while i + 16 <= n {
        let x_v = _mm256_loadu_si256(x.as_ptr().add(i) as *const __m256i);
        let t_lo = _mm256_mullo_epi16(x_v, c_vec);
        let t_hi = _mm256_mulhi_epi16(x_v, c_vec);
        let u = _mm256_mullo_epi16(t_lo, qinv_vec);
        let result = _mm256_sub_epi16(t_hi, _mm256_mulhi_epi16(u, q_vec));
        _mm256_storeu_si256(z.as_mut_ptr().add(i) as *mut __m256i, result);
        i += 16;
    }
    let qinv = montgomery::QINV_4591 as i32;
    let q32 = montgomery::Q4591 as i32;
    while i < n {
        let t = x[i] as i32 * c_std as i32;
        let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
        z[i] = ((t - (u as i32) * q32) >> 16) as i16;
        i += 1;
    }
}

/// NEON product_from_mont: 8 i16 elements at a time.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn product_from_mont_neon(z: &mut [i16], n: usize, x: &[i16], c_std: i16) {
    unsafe {
        use core::arch::aarch64::*;

        let qinv_vec = vdupq_n_s16(montgomery::QINV_4591);
        let q_vec = vdupq_n_s16(montgomery::Q4591 as i16);
        let c_vec = vdupq_n_s16(c_std);

        let mut i = 0usize;
        while i + 8 <= n {
            let x_v = vld1q_s16(x.as_ptr().add(i));
            let result = montgomery::montmul_x8(x_v, c_vec, qinv_vec, q_vec);
            vst1q_s16(z.as_mut_ptr().add(i), result);
            i += 8;
        }
        let qinv = montgomery::QINV_4591 as i32;
        let q32 = montgomery::Q4591 as i32;
        while i < n {
            let t = x[i] as i32 * c_std as i32;
            let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
            z[i] = ((t - (u as i32) * q32) >> 16) as i16;
            i += 1;
        }
    }
}

#[cfg(test)]
#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;
    use rand::RngExt;

    #[test]
    fn test_fused_mont_shift_random_values() {
        let mut rng = rand::rng();
        // Use wider (-q, q) range to simulate accumulated values after many iterations
        for n in [762usize, 1524] {
            for _ in 0..500 {
                let mut z: Vec<i16> = (0..n).map(|_| rng.random_range(-4590i16..4591)).collect();
                let y: Vec<i16> = (0..n).map(|_| rng.random_range(-4590i16..4591)).collect();
                let c_mont: i16 = rng.random_range(-4590i16..4591);

                let mut z_scalar = z.clone();
                minus_product_shift_mont_scalar(&mut z_scalar, n, &y, c_mont);

                #[cfg(all(
                    target_arch = "x86_64",
                    target_feature = "avx2",
                    not(feature = "force-scalar")
                ))]
                unsafe {
                    minus_product_shift_mont_avx2(&mut z, n, &y, c_mont);
                }

                #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
                unsafe {
                    minus_product_shift_mont_neon(&mut z, n, &y, c_mont);
                }

                for i in 0..n {
                    let diff = (z[i] as i32 - z_scalar[i] as i32).abs();
                    assert!(
                        diff == 0 || diff == 4591,
                        "MISMATCH at index {i}: simd={}, scalar={}, n={n}, c_mont={c_mont}",
                        z[i],
                        z_scalar[i]
                    );
                }
            }
        }
    }
}
