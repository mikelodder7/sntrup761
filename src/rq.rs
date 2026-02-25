pub mod encoding;
pub mod modq;
pub(crate) mod montgomery;
pub(crate) mod ntt;
mod vector;

use crate::P;

#[inline(always)]
fn swap_int(x: isize, y: isize, mask: isize) -> (isize, isize) {
    let t = mask & (x ^ y);
    (x ^ t, y ^ t)
}

#[inline(always)]
fn smaller_mask(x: isize, y: isize) -> isize {
    (x - y) >> 31
}

#[allow(clippy::cast_possible_wrap)]
pub fn reciprocal3(s: [i8; P]) -> [i16; P] {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    {
        return reciprocal3_mont(s);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    {
        return reciprocal3_mont(s);
    }
    #[allow(unreachable_code)]
    reciprocal3_scalar(s)
}

#[allow(clippy::cast_possible_wrap)]
fn reciprocal3_scalar(s: [i8; P]) -> [i16; P] {
    const LOOPS: usize = 2 * P + 1;
    let mut r = [0i16; P];
    let mut f = [0i16; P + 1];
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;
    let mut g = [0i16; P + 1];
    for i in 0..P {
        g[i] = (3 * s[i]) as i16;
    }
    let mut d = P as isize;
    let mut e = P as isize;
    let mut u = [0i16; LOOPS + 1];
    let mut v = [0i16; LOOPS + 1];
    v[0] = 1;

    for _ in 0..LOOPS {
        let c = modq::quotient(g[P], f[P]);
        vector::minus_product_shift(&mut g, P + 1, &f, c);
        vector::minus_product_shift(&mut v, LOOPS + 1, &u, c);
        e -= 1;
        let m = smaller_mask(e, d) & modq::mask_set(g[P]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, P + 1, m);
        vector::swap(&mut u, &mut v, LOOPS + 1, m);
    }
    vector::product(&mut r, P, &u[P..], modq::reciprocal(f[P]));
    smaller_mask(0, d);
    r
}

/// Montgomery-domain reciprocal3: uses i16 Montgomery multiply (SIMD)
/// instead of i32 Barrett, increasing throughput for the inner loop.
#[cfg(all(
    not(feature = "force-scalar"),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        target_arch = "aarch64"
    )
))]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn reciprocal3_mont(s: [i8; P]) -> [i16; P] {
    const LOOPS: usize = 2 * P + 1;
    const R_MOD_Q: i16 = (montgomery::R % montgomery::Q4591) as i16;

    let mut r = [0i16; P];

    let mut f = [0i16; P + 1];
    f[0] = modq::freeze(-(R_MOD_Q as i32));
    f[1] = modq::freeze(-(R_MOD_Q as i32));
    f[P] = R_MOD_Q;

    let mut g = [0i16; P + 1];
    for i in 0..P {
        g[i] = modq::product((3 * s[i]) as i16, R_MOD_Q);
    }

    let mut d = P as isize;
    let mut e = P as isize;
    let mut u = [0i16; LOOPS + 1];
    let mut v = [0i16; LOOPS + 1];
    v[0] = R_MOD_Q;

    // Precomputed Montgomery reduction constants
    let qinv32 = montgomery::QINV_4591 as i32;
    let q32 = montgomery::Q4591 as i32;

    for _ in 0..LOOPS {
        // Inline Montgomery reduction to convert leading coefficients to standard form
        let g_raw = {
            let a32 = g[P] as i32;
            let u = ((a32 as i16) as i32).wrapping_mul(qinv32) as i16;
            let r = (a32 - (u as i32) * q32) >> 16;
            if r < 0 {
                (r + q32) as i16
            } else {
                r as i16
            }
        };
        let g_std = modq::freeze(g_raw as i32);
        let f_raw = {
            let a32 = f[P] as i32;
            let u = ((a32 as i16) as i32).wrapping_mul(qinv32) as i16;
            let r = (a32 - (u as i32) * q32) >> 16;
            if r < 0 {
                (r + q32) as i16
            } else {
                r as i16
            }
        };
        let f_std = modq::freeze(f_raw as i32);
        let c = modq::quotient(g_std, f_std);
        let c_mont = modq::product(c, R_MOD_Q);
        vector::minus_product_shift_mont(&mut g, P + 1, &f, c_mont);
        vector::minus_product_shift_mont(&mut v, LOOPS + 1, &u, c_mont);
        e -= 1;
        // Normalize g[P] for mask_set: SIMD clamp can leave -q (≡ 0 mod q)
        // as a non-zero bit pattern. Add q if negative to map to [0, q).
        let gp = g[P] as i32;
        let m = smaller_mask(e, d) & modq::mask_set((gp + ((gp >> 31) & q32)) as i16);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, P + 1, m);
        vector::swap(&mut u, &mut v, LOOPS + 1, m);
    }

    // Final: convert f[P] from Montgomery form
    let f_raw = {
        let a32 = f[P] as i32;
        let u = ((a32 as i16) as i32).wrapping_mul(qinv32) as i16;
        let r = (a32 - (u as i32) * q32) >> 16;
        if r < 0 {
            (r + q32) as i16
        } else {
            r as i16
        }
    };
    let f_std = modq::freeze(f_raw as i32);
    let rec = modq::reciprocal(f_std);
    vector::product_from_mont(&mut r, P, &u[P..], rec);

    smaller_mask(0, d);
    r
}

#[allow(clippy::cast_possible_truncation)]
pub fn round3(h: &mut [i16; P]) {
    for coeff in h.iter_mut() {
        let inner = 21846i32 * (*coeff as i32 + 2295);
        *coeff = (((inner + 32768) >> 16) * 3 - 2295) as i16;
    }
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i16; P], f: [i16; P], g: [i8; P]) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 availability verified by cfg target_feature
    unsafe {
        return mult_avx2(h, &f, &g);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return mult_neon(h, &f, &g);
    }
    #[allow(unreachable_code)]
    mult_scalar(h, &f, &g);
}

fn mult_scalar(h: &mut [i16; P], f: &[i16; P], g: &[i8; P]) {
    let mut fg = [0i16; P * 2 - 1];
    for i in 0..P {
        let mut r = 0i32;
        for j in 0..=i {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = modq::freeze(r);
    }
    for i in P..(P * 2 - 1) {
        let mut r = 0i32;
        for j in (i - P + 1)..P {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = modq::freeze(r);
    }
    for i in (P..(P * 2) - 1).rev() {
        fg[i - P] = modq::freeze(fg[i - P] as i32 + fg[i] as i32);
        fg[i - P + 1] = modq::freeze(fg[i - P + 1] as i32 + fg[i] as i32);
    }
    h[..P].copy_from_slice(&fg[..P]);
}

/// Column-major schoolbook multiplication with AVX2.
/// Processes 8 i32 multiply-accumulates per SIMD instruction.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]
unsafe fn mult_avx2(h: &mut [i16; P], f: &[i16; P], g: &[i8; P]) {
    use core::arch::x86_64::*;

    // Pad to multiples of 8 so SIMD loops need no remainder handling
    const G_PAD: usize = (P + 7) & !7; // 768
    const FG_PAD: usize = P + G_PAD; // 1529 (>= 2P-1 = 1521)
    const FG_LEN: usize = P * 2 - 1; // 1521

    let mut g_pad = [0i8; G_PAD];
    g_pad[..P].copy_from_slice(g);
    let mut fg = [0i32; FG_PAD];

    // Accumulate f[j]*g[k] into fg[j+k]
    for j in 0..P {
        let fj = _mm256_set1_epi32(f[j] as i32);
        let mut k = 0usize;
        while k < G_PAD {
            let gb = _mm_loadl_epi64(g_pad.as_ptr().add(k) as *const __m128i);
            let gk = _mm256_cvtepi8_epi32(gb);
            let prod = _mm256_mullo_epi32(fj, gk);
            let acc = _mm256_loadu_si256(fg.as_ptr().add(j + k) as *const __m256i);
            _mm256_storeu_si256(
                fg.as_mut_ptr().add(j + k) as *mut __m256i,
                _mm256_add_epi32(acc, prod),
            );
            k += 8;
        }
    }

    // Vectorized Barrett freeze: i32 -> i16
    let qv = _mm256_set1_epi32(crate::Q as i32);
    let k228 = _mm256_set1_epi32(228);
    let k58470 = _mm256_set1_epi32(58470);
    let k134m = _mm256_set1_epi32(134_217_728);

    let mut fg16 = [0i16; FG_LEN];
    let mut i = 0usize;
    while i + 16 <= FG_LEN {
        let a0 = _mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i);
        let a1 = _mm256_loadu_si256(fg.as_ptr().add(i + 8) as *const __m256i);

        // freeze(a) = a - Q*((228*a)>>20) then b - Q*((58470*b+134M)>>28)
        let t = _mm256_srai_epi32(_mm256_mullo_epi32(a0, k228), 20);
        let b0 = _mm256_sub_epi32(a0, _mm256_mullo_epi32(t, qv));
        let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b0, k58470), k134m), 28);
        let r0 = _mm256_sub_epi32(b0, _mm256_mullo_epi32(t, qv));

        let t = _mm256_srai_epi32(_mm256_mullo_epi32(a1, k228), 20);
        let b1 = _mm256_sub_epi32(a1, _mm256_mullo_epi32(t, qv));
        let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b1, k58470), k134m), 28);
        let r1 = _mm256_sub_epi32(b1, _mm256_mullo_epi32(t, qv));

        // Pack 8+8 i32 -> 16 i16 and fix AVX2 lane ordering
        let packed = _mm256_permute4x64_epi64(_mm256_packs_epi32(r0, r1), 0xD8);
        _mm256_storeu_si256(fg16.as_mut_ptr().add(i) as *mut __m256i, packed);
        i += 16;
    }
    while i < FG_LEN {
        fg16[i] = modq::freeze(fg[i]);
        i += 1;
    }

    // Reduction (scalar — sequential dependencies prevent vectorization)
    for i in (P..(P * 2) - 1).rev() {
        fg16[i - P] = modq::freeze(fg16[i - P] as i32 + fg16[i] as i32);
        fg16[i - P + 1] = modq::freeze(fg16[i - P + 1] as i32 + fg16[i] as i32);
    }
    h[..P].copy_from_slice(&fg16[..P]);
}

/// Column-major schoolbook multiplication with NEON.
/// Processes 4 i32 multiply-accumulates per SIMD instruction.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i16; P], f: &[i16; P], g: &[i8; P]) {
    use core::arch::aarch64::*;

    // Pad to multiples of 4 so SIMD loops need no remainder handling
    const G_PAD: usize = (P + 3) & !3; // 764
    const FG_PAD: usize = P + G_PAD; // 1525 (>= 2P-1 = 1521)
    const FG_LEN: usize = P * 2 - 1; // 1521

    let mut g_pad = [0i8; G_PAD];
    g_pad[..P].copy_from_slice(g);
    let mut fg = [0i32; FG_PAD];

    // Accumulate f[j]*g[k] into fg[j+k]
    for j in 0..P {
        let fj = vdupq_n_s32(f[j] as i32);
        let mut k = 0usize;
        while k + 4 <= G_PAD {
            // Sign-extend 4 i8 -> i16 -> i32
            let gb = vld1_s8(g_pad.as_ptr().add(k));
            let g16 = vmovl_s8(gb);
            let gk = vmovl_s16(vget_low_s16(g16));
            let prod = vmulq_s32(fj, gk);
            let acc = vld1q_s32(fg.as_ptr().add(j + k));
            vst1q_s32(fg.as_mut_ptr().add(j + k), vaddq_s32(acc, prod));
            k += 4;
        }
    }

    // Vectorized Barrett freeze: i32 -> i16
    let qv = vdupq_n_s32(crate::Q as i32);
    let k228 = vdupq_n_s32(228);
    let k58470 = vdupq_n_s32(58470);
    let k134m = vdupq_n_s32(134_217_728);

    let mut fg16 = [0i16; FG_LEN];
    let mut i = 0usize;
    while i + 8 <= FG_LEN {
        // Process 8 values: two batches of 4 i32 → 8 i16
        let a0 = vld1q_s32(fg.as_ptr().add(i));
        let a1 = vld1q_s32(fg.as_ptr().add(i + 4));

        let t = vshrq_n_s32(vmulq_s32(a0, k228), 20);
        let b0 = vsubq_s32(a0, vmulq_s32(t, qv));
        let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b0, k58470), k134m), 28);
        let r0 = vsubq_s32(b0, vmulq_s32(t, qv));

        let t = vshrq_n_s32(vmulq_s32(a1, k228), 20);
        let b1 = vsubq_s32(a1, vmulq_s32(t, qv));
        let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b1, k58470), k134m), 28);
        let r1 = vsubq_s32(b1, vmulq_s32(t, qv));

        // Pack 4+4 i32 -> 8 i16 (naturally ordered, no permute needed)
        let packed = vcombine_s16(vmovn_s32(r0), vmovn_s32(r1));
        vst1q_s16(fg16.as_mut_ptr().add(i), packed);
        i += 8;
    }
    while i < FG_LEN {
        fg16[i] = modq::freeze(fg[i]);
        i += 1;
    }

    // Reduction (scalar — sequential dependencies prevent vectorization)
    for i in (P..(P * 2) - 1).rev() {
        fg16[i - P] = modq::freeze(fg16[i - P] as i32 + fg16[i] as i32);
        fg16[i - P + 1] = modq::freeze(fg16[i - P + 1] as i32 + fg16[i] as i32);
    }
    h[..P].copy_from_slice(&fg16[..P]);
}
