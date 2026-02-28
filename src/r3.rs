pub mod mod3;
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
pub fn reciprocal(s: [i8; P]) -> (isize, [i8; P]) {
    const LOOPS: usize = 2 * P + 1;
    let mut r = [0i8; P];
    let mut f = [0i8; P + 1];
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    let mut g = [0i8; P + 1];
    g[..P].clone_from_slice(&s[..P]);
    let mut d = P as isize;
    let mut e = P as isize;
    let mut u = [0i8; LOOPS + 1];
    let mut v = [0i8; LOOPS + 1];
    v[0] = 1;

    for _ in 0..LOOPS {
        let c = mod3::quotient(g[P], f[P]);
        vector::minus_product_shift(&mut g, P + 1, &f, c);
        vector::minus_product_shift(&mut v, LOOPS + 1, &u, c);
        e -= 1;
        let m = smaller_mask(e, d) & mod3::mask_set(g[P]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, P + 1, m);
        vector::swap(&mut u, &mut v, LOOPS + 1, m);
    }

    vector::product(&mut r, P, &u[P..], mod3::reciprocal(f[P]));
    (smaller_mask(0, d), r)
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i8; P], f: [i8; P], g: [i8; P]) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
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

fn mult_scalar(h: &mut [i8; P], f: &[i8; P], g: &[i8; P]) {
    let mut fg = [0i8; P * 2 - 1];
    for i in 0..P {
        let mut r = 0i32;
        for j in 0..=i {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = mod3::freeze(r);
    }
    for i in P..(P * 2 - 1) {
        let mut r = 0i32;
        for j in (i - P + 1)..P {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = mod3::freeze(r);
    }
    for i in (P..(P * 2) - 1).rev() {
        fg[i - P] = mod3::freeze(fg[i - P] as i32 + fg[i] as i32);
        fg[i - P + 1] = mod3::freeze(fg[i - P + 1] as i32 + fg[i] as i32);
    }
    h[..P].copy_from_slice(&fg[..P]);
}

/// Column-major schoolbook multiplication with AVX2 for R3 polynomials.
/// Uses _mm256_sign_epi16 for {-1,0,1} multiplication and i16 accumulators.
/// Processes 16 coefficients per SIMD instruction.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_avx2(h: &mut [i8; P], f: &[i8; P], g: &[i8; P]) {
    use core::arch::x86_64::*;

    const G_PAD: usize = (P + 15) & !15; // 768, multiple of 16
    const FG_PAD: usize = P + G_PAD; // 1529 (>= 2P-1 = 1521)
    const FG_LEN: usize = P * 2 - 1; // 1521

    // Sign-extend g to i16, padded
    let mut g_pad = [0i16; G_PAD];
    for i in 0..P {
        g_pad[i] = g[i] as i16;
    }

    // i16 accumulators (max value: ±761, fits in i16)
    let mut fg = [0i16; FG_PAD];

    // Column-major accumulation: fg[j+k] += f[j] * g[k]
    for j in 0..P {
        let fj = _mm256_set1_epi16(f[j] as i16);
        let mut k = 0usize;
        while k + 16 <= G_PAD {
            let gk = _mm256_loadu_si256(g_pad.as_ptr().add(k) as *const __m256i);
            // sign_epi16: if fj>0 → gk, if fj==0 → 0, if fj<0 → -gk
            let prod = _mm256_sign_epi16(gk, fj);
            let acc = _mm256_loadu_si256(fg.as_ptr().add(j + k) as *const __m256i);
            _mm256_storeu_si256(
                fg.as_mut_ptr().add(j + k) as *mut __m256i,
                _mm256_add_epi16(acc, prod),
            );
            k += 16;
        }
    }

    // Vectorized mod-3 freeze: mulhrs(a, 10923) gives floor((a*10923+16384)/32768)
    // which is the correct quotient for |a| <= 761.
    // Result: a - 3*q is in {-1, 0, 1}.
    let k10923 = _mm256_set1_epi16(10923);
    let three16 = _mm256_set1_epi16(3);

    let mut fg8 = [0i8; FG_LEN];
    let mut i = 0usize;
    while i + 32 <= FG_LEN {
        // Process 32 values: two batches of 16 i16 → 32 i8
        let a0 = _mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i);
        let q0 = _mm256_mulhrs_epi16(a0, k10923);
        let r0 = _mm256_sub_epi16(a0, _mm256_mullo_epi16(q0, three16));

        let a1 = _mm256_loadu_si256(fg.as_ptr().add(i + 16) as *const __m256i);
        let q1 = _mm256_mulhrs_epi16(a1, k10923);
        let r1 = _mm256_sub_epi16(a1, _mm256_mullo_epi16(q1, three16));

        // Pack 16+16 i16 → 32 i8, fix AVX2 lane ordering
        let packed = _mm256_permute4x64_epi64(_mm256_packs_epi16(r0, r1), 0xD8);
        _mm256_storeu_si256(fg8.as_mut_ptr().add(i) as *mut __m256i, packed);
        i += 32;
    }
    while i < FG_LEN {
        fg8[i] = mod3::freeze(fg[i] as i32);
        i += 1;
    }

    // Reduction: x^P ≡ x + 1 (mod x^P - x - 1)
    for i in (P..(P * 2) - 1).rev() {
        fg8[i - P] = mod3::freeze(fg8[i - P] as i32 + fg8[i] as i32);
        fg8[i - P + 1] = mod3::freeze(fg8[i - P + 1] as i32 + fg8[i] as i32);
    }
    h[..P].copy_from_slice(&fg8[..P]);
}

/// Column-major schoolbook multiplication with NEON for R3 polynomials.
/// Uses vmulq_s16 for {-1,0,1} multiplication and i16 accumulators.
/// Processes 8 coefficients per SIMD instruction.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i8; P], f: &[i8; P], g: &[i8; P]) {
    unsafe {
        use core::arch::aarch64::*;

        const G_PAD: usize = (P + 7) & !7; // 768, multiple of 8
        const FG_PAD: usize = P + G_PAD; // 1529 (>= 2P-1 = 1521)
        const FG_LEN: usize = P * 2 - 1; // 1521

        // Sign-extend g to i16, padded
        let mut g_pad = [0i16; G_PAD];
        for i in 0..P {
            g_pad[i] = g[i] as i16;
        }

        // i16 accumulators (max value: ±761, fits in i16)
        let mut fg = [0i16; FG_PAD];

        // Column-major accumulation: fg[j+k] += f[j] * g[k]
        // vmulq_s16(gk, fj): for fj in {-1,0,1} this produces correct signed product
        for j in 0..P {
            let fj = vdupq_n_s16(f[j] as i16);
            let mut k = 0usize;
            while k + 8 <= G_PAD {
                let gk = vld1q_s16(g_pad.as_ptr().add(k));
                let prod = vmulq_s16(gk, fj);
                let acc = vld1q_s16(fg.as_ptr().add(j + k));
                vst1q_s16(fg.as_mut_ptr().add(j + k), vaddq_s16(acc, prod));
                k += 8;
            }
        }

        // Vectorized mod-3 freeze: vqrdmulhq_s16(a, 10923) gives correct quotient
        // for |a| <= 761.  Result: a - 3*q is in {-1, 0, 1}.
        let k10923 = vdupq_n_s16(10923);
        let three16 = vdupq_n_s16(3);

        let mut fg8 = [0i8; FG_LEN];
        let mut i = 0usize;
        while i + 16 <= FG_LEN {
            // Process 16 values: two batches of 8 i16 → 16 i8
            let a0 = vld1q_s16(fg.as_ptr().add(i));
            let q0 = vqrdmulhq_s16(a0, k10923);
            let r0 = vsubq_s16(a0, vmulq_s16(q0, three16));

            let a1 = vld1q_s16(fg.as_ptr().add(i + 8));
            let q1 = vqrdmulhq_s16(a1, k10923);
            let r1 = vsubq_s16(a1, vmulq_s16(q1, three16));

            // Pack 8+8 i16 → 16 i8 (naturally ordered, no permute needed)
            let packed = vcombine_s8(vqmovn_s16(r0), vqmovn_s16(r1));
            vst1q_s8(fg8.as_mut_ptr().add(i), packed);
            i += 16;
        }
        while i < FG_LEN {
            fg8[i] = mod3::freeze(fg[i] as i32);
            i += 1;
        }

        // Reduction: x^P ≡ x + 1 (mod x^P - x - 1)
        for i in (P..(P * 2) - 1).rev() {
            fg8[i - P] = mod3::freeze(fg8[i - P] as i32 + fg8[i] as i32);
            fg8[i - P + 1] = mod3::freeze(fg8[i - P + 1] as i32 + fg8[i] as i32);
        }
        h[..P].copy_from_slice(&fg8[..P]);
    }
}
