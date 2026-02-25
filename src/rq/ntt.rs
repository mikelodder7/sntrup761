#![allow(
    dead_code,
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_range_loop
)]

/// NTT-512 for polynomial multiplication over Z[x].
///
/// Uses Good's permutation to decompose 768-point multiplication into
/// three 256-point sub-multiplications, each padded to 512 for NTT.
/// Two NTT primes (7681 and 10753) with CRT reconstruction to mod 4591.
use super::montgomery::*;

/// NTT size
const N: usize = 512;
/// Number of butterfly stages: log2(512) = 9
const LOG_N: usize = 9;

// -----------------------------------------------------------------------
// Twiddle factor tables (computed at compile time)
// -----------------------------------------------------------------------

/// Forward twiddle factors for NTT-512.
/// Layout: for each stage s (0..9), N/2 = 256 twiddle entries are stored contiguously.
/// Stage s has groups of size 2^(s+1), with 2^s butterflies per group.
/// Total entries: 9 * 256 = 2304.
const TWIDDLE_7681: [i16; LOG_N * (N / 2)] = compute_twiddles(P7681);
const TWIDDLE_10753: [i16; LOG_N * (N / 2)] = compute_twiddles(P10753);

/// Inverse twiddle factors for inverse NTT.
const INV_TWIDDLE_7681: [i16; LOG_N * (N / 2)] = compute_inv_twiddles(P7681);
const INV_TWIDDLE_10753: [i16; LOG_N * (N / 2)] = compute_inv_twiddles(P10753);

/// 1/N in Montgomery form for each prime (for inverse NTT normalization).
const NINV_MONT_7681: i16 = to_mont(mod_inverse(N as i64, P7681), P7681);
const NINV_MONT_10753: i16 = to_mont(mod_inverse(N as i64, P10753), P10753);

/// 1/N as plain value (not Montgomery form) for combined normalize+demontgomerize.
/// montmul(x_mont, NINV_PLAIN) = x * R * (1/N) * R^{-1} = x/N (plain)
#[allow(clippy::cast_possible_truncation)]
const NINV_PLAIN_7681: i16 = mod_inverse(N as i64, P7681) as i16;
#[allow(clippy::cast_possible_truncation)]
const NINV_PLAIN_10753: i16 = mod_inverse(N as i64, P10753) as i16;

/// Compute forward NTT twiddle factors for prime q in Montgomery form.
/// Uses iterative Cooley-Tukey DIT layout.
const fn compute_twiddles(q: i64) -> [i16; LOG_N * (N / 2)] {
    let omega = primitive_root_512(q);
    let mut table = [0i16; LOG_N * (N / 2)];

    // Precompute powers of omega in Montgomery form
    let mut omega_powers = [0i16; N];
    let mut i = 0;
    while i < N {
        omega_powers[i] = to_mont(mod_pow(omega, i as i64, q), q);
        i += 1;
    }

    let mut s = 0;
    while s < LOG_N {
        let half_len = 1usize << s;
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        let mut g = 0;
        while g < num_groups {
            let mut j = 0;
            while j < half_len {
                let tw_idx = (j * num_groups) % N;
                table[base + g * half_len + j] = omega_powers[tw_idx];
                j += 1;
            }
            g += 1;
        }
        s += 1;
    }
    table
}

/// Compute inverse NTT twiddle factors (using omega^{-1}).
const fn compute_inv_twiddles(q: i64) -> [i16; LOG_N * (N / 2)] {
    let omega = primitive_root_512(q);
    let omega_inv = mod_inverse(omega, q);
    let mut table = [0i16; LOG_N * (N / 2)];

    let mut omega_inv_powers = [0i16; N];
    let mut i = 0;
    while i < N {
        omega_inv_powers[i] = to_mont(mod_pow(omega_inv, i as i64, q), q);
        i += 1;
    }

    // Inverse NTT uses GS DIF: stages process in reverse order
    let mut s = 0;
    while s < LOG_N {
        let half_len = 1usize << (LOG_N - 1 - s);
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        let mut g = 0;
        while g < num_groups {
            let mut j = 0;
            while j < half_len {
                let tw_idx = (j * num_groups) % N;
                table[base + g * half_len + j] = omega_inv_powers[tw_idx];
                j += 1;
            }
            g += 1;
        }
        s += 1;
    }
    table
}

// -----------------------------------------------------------------------
// Bit-reversal permutation
// -----------------------------------------------------------------------

/// Bit-reverse a LOG_N-bit integer.
const fn bit_reverse(mut x: usize) -> usize {
    let mut result = 0;
    let mut i = 0;
    while i < LOG_N {
        result = (result << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    result
}

/// In-place bit-reversal permutation of an N-element array.
fn bit_reverse_permutation(a: &mut [i16; N]) {
    for i in 0..N {
        let j = bit_reverse(i);
        if i < j {
            a.swap(i, j);
        }
    }
}

// -----------------------------------------------------------------------
// Scalar NTT implementation (fallback + used for small stages in AVX2)
// -----------------------------------------------------------------------

/// Forward NTT-512 (Cooley-Tukey DIT), scalar.
/// Input/output in Montgomery form.
fn ntt512_scalar(a: &mut [i16; N], twiddles: &[i16; LOG_N * (N / 2)], q: i64) {
    bit_reverse_permutation(a);
    let q32 = q as i32;
    for s in 0..LOG_N {
        let half_len = 1 << s;
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        for g in 0..num_groups {
            for j in 0..half_len {
                let tw = twiddles[base + g * half_len + j];
                let idx0 = g * (2 * half_len) + j;
                let idx1 = idx0 + half_len;

                let u = a[idx0] as i32;
                let v = montmul_scalar(a[idx1], tw, q) as i32;

                // Butterfly with reduction to avoid i16 overflow
                let mut s0 = u + v;
                let mut s1 = u - v;
                // Keep in roughly (-q, q) range
                if s0 >= q32 {
                    s0 -= q32;
                }
                if s0 < -q32 {
                    s0 += q32;
                }
                if s1 >= q32 {
                    s1 -= q32;
                }
                if s1 < -q32 {
                    s1 += q32;
                }
                a[idx0] = s0 as i16;
                a[idx1] = s1 as i16;
            }
        }
    }
}

/// Inverse NTT-512 (Gentleman-Sande DIF), scalar.
fn intt512_scalar(a: &mut [i16; N], inv_twiddles: &[i16; LOG_N * (N / 2)], ninv: i16, q: i64) {
    let q32 = q as i32;
    for s in 0..LOG_N {
        let half_len = 1 << (LOG_N - 1 - s);
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        for g in 0..num_groups {
            for j in 0..half_len {
                let tw = inv_twiddles[base + g * half_len + j];
                let idx0 = g * (2 * half_len) + j;
                let idx1 = idx0 + half_len;

                let u = a[idx0] as i32;
                let v = a[idx1] as i32;

                let mut s0 = u + v;
                if s0 >= q32 {
                    s0 -= q32;
                }
                if s0 < -q32 {
                    s0 += q32;
                }
                a[idx0] = s0 as i16;
                let mut d = u - v;
                if d >= q32 {
                    d -= q32;
                }
                if d < -q32 {
                    d += q32;
                }
                a[idx1] = montmul_scalar(d as i16, tw, q);
            }
        }
    }

    // DIF produces output in bit-reversed order; undo it
    bit_reverse_permutation(a);

    // Multiply by 1/N and convert from Montgomery form to plain [0, q)
    for val in a.iter_mut() {
        let normed = montmul_scalar(*val, ninv, q);
        // from_mont: montmul with 1 (= R^{-1} scaling)
        // normed is in Montgomery form: normed = (plain_val * R) mod q
        // We need to extract plain_val = normed * R^{-1} mod q
        // This is equivalent to Montgomery reduction of normed (treating it as a 16-bit value)
        *val = from_mont(mont_reduce(normed, q), q);
    }
}

// -----------------------------------------------------------------------
// AVX2 NTT implementation
// -----------------------------------------------------------------------

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn ntt512_avx2(a: &mut [i16; N], twiddles: &[i16; LOG_N * (N / 2)], q_val: i64) {
    use core::arch::x86_64::*;

    bit_reverse_permutation(a);

    let qv = _mm256_set1_epi16(q_val as i16);
    let qinv = if q_val == P7681 {
        _mm256_set1_epi16(QINV_7681)
    } else {
        _mm256_set1_epi16(QINV_10753)
    };
    // Precompute constants for signed reduction from (-2q, 2q) to (-q, q)
    let ones = _mm256_set1_epi16(1);
    let qm1 = _mm256_sub_epi16(qv, ones); // q - 1
    let neg_q = _mm256_sub_epi16(_mm256_setzero_si256(), qv); // -q

    for s in 0..LOG_N {
        let half_len = 1usize << s;
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        if half_len >= 16 {
            // Process 16 butterflies at a time
            for g in 0..num_groups {
                let mut j = 0;
                while j + 16 <= half_len {
                    let tw = _mm256_loadu_si256(
                        twiddles.as_ptr().add(base + g * half_len + j) as *const __m256i
                    );
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;

                    let u = _mm256_loadu_si256(a.as_ptr().add(idx0) as *const __m256i);
                    let v_raw = _mm256_loadu_si256(a.as_ptr().add(idx1) as *const __m256i);
                    let v = montmul_x16(v_raw, tw, qinv, qv);

                    let sum = _mm256_add_epi16(u, v);
                    let diff = _mm256_sub_epi16(u, v);

                    // Signed reduction: (-2q, 2q) -> (-q, q)
                    // Subtract q where sum >= q
                    let mask = _mm256_cmpgt_epi16(sum, qm1);
                    let sum = _mm256_sub_epi16(sum, _mm256_and_si256(mask, qv));
                    // Add q where sum < -q
                    let mask = _mm256_cmpgt_epi16(neg_q, sum);
                    let sum = _mm256_add_epi16(sum, _mm256_and_si256(mask, qv));

                    let mask = _mm256_cmpgt_epi16(diff, qm1);
                    let diff = _mm256_sub_epi16(diff, _mm256_and_si256(mask, qv));
                    let mask = _mm256_cmpgt_epi16(neg_q, diff);
                    let diff = _mm256_add_epi16(diff, _mm256_and_si256(mask, qv));

                    _mm256_storeu_si256(a.as_mut_ptr().add(idx0) as *mut __m256i, sum);
                    _mm256_storeu_si256(a.as_mut_ptr().add(idx1) as *mut __m256i, diff);
                    j += 16;
                }
                // Scalar remainder (with reduction)
                let q32 = q_val as i32;
                while j < half_len {
                    let tw = twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = montmul_scalar(a[idx1], tw, q_val) as i32;
                    let mut s0 = u + v;
                    let mut s1 = u - v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    if s1 >= q32 {
                        s1 -= q32;
                    }
                    if s1 < -q32 {
                        s1 += q32;
                    }
                    a[idx0] = s0 as i16;
                    a[idx1] = s1 as i16;
                    j += 1;
                }
            }
        } else {
            // Small stages: use scalar (avoids complex shuffle logic)
            let q32 = q_val as i32;
            for g in 0..num_groups {
                for j in 0..half_len {
                    let tw = twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = montmul_scalar(a[idx1], tw, q_val) as i32;
                    let mut s0 = u + v;
                    let mut s1 = u - v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    if s1 >= q32 {
                        s1 -= q32;
                    }
                    if s1 < -q32 {
                        s1 += q32;
                    }
                    a[idx0] = s0 as i16;
                    a[idx1] = s1 as i16;
                }
            }
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn intt512_avx2(
    a: &mut [i16; N],
    inv_twiddles: &[i16; LOG_N * (N / 2)],
    _ninv: i16,
    q_val: i64,
) {
    use core::arch::x86_64::*;

    let qv = _mm256_set1_epi16(q_val as i16);
    let qinv = if q_val == P7681 {
        _mm256_set1_epi16(QINV_7681)
    } else {
        _mm256_set1_epi16(QINV_10753)
    };
    let ones = _mm256_set1_epi16(1);
    let qm1 = _mm256_sub_epi16(qv, ones);
    let neg_q = _mm256_sub_epi16(_mm256_setzero_si256(), qv);

    for s in 0..LOG_N {
        let half_len = 1 << (LOG_N - 1 - s);
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        if half_len >= 16 {
            for g in 0..num_groups {
                let mut j = 0;
                while j + 16 <= half_len {
                    let tw = _mm256_loadu_si256(
                        inv_twiddles.as_ptr().add(base + g * half_len + j) as *const __m256i
                    );
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;

                    let u = _mm256_loadu_si256(a.as_ptr().add(idx0) as *const __m256i);
                    let v = _mm256_loadu_si256(a.as_ptr().add(idx1) as *const __m256i);

                    // DIF butterfly: a' = u + v, b' = (u - v) * tw
                    let sum = _mm256_add_epi16(u, v);
                    let diff = _mm256_sub_epi16(u, v);

                    // Reduce sum to (-q, q)
                    let mask = _mm256_cmpgt_epi16(sum, qm1);
                    let sum = _mm256_sub_epi16(sum, _mm256_and_si256(mask, qv));
                    let mask = _mm256_cmpgt_epi16(neg_q, sum);
                    let sum = _mm256_add_epi16(sum, _mm256_and_si256(mask, qv));

                    // Reduce diff to (-q, q) before montmul
                    let mask = _mm256_cmpgt_epi16(diff, qm1);
                    let diff = _mm256_sub_epi16(diff, _mm256_and_si256(mask, qv));
                    let mask = _mm256_cmpgt_epi16(neg_q, diff);
                    let diff = _mm256_add_epi16(diff, _mm256_and_si256(mask, qv));

                    _mm256_storeu_si256(a.as_mut_ptr().add(idx0) as *mut __m256i, sum);
                    _mm256_storeu_si256(
                        a.as_mut_ptr().add(idx1) as *mut __m256i,
                        montmul_x16(diff, tw, qinv, qv),
                    );
                    j += 16;
                }
                let q32 = q_val as i32;
                while j < half_len {
                    let tw = inv_twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = a[idx1] as i32;
                    let mut s0 = u + v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    a[idx0] = s0 as i16;
                    let mut d = u - v;
                    if d >= q32 {
                        d -= q32;
                    }
                    if d < -q32 {
                        d += q32;
                    }
                    a[idx1] = montmul_scalar(d as i16, tw, q_val);
                    j += 1;
                }
            }
        } else {
            let q32 = q_val as i32;
            for g in 0..num_groups {
                for j in 0..half_len {
                    let tw = inv_twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = a[idx1] as i32;
                    let mut s0 = u + v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    a[idx0] = s0 as i16;
                    let mut d = u - v;
                    if d >= q32 {
                        d -= q32;
                    }
                    if d < -q32 {
                        d += q32;
                    }
                    a[idx1] = montmul_scalar(d as i16, tw, q_val);
                }
            }
        }
    }

    // Bit-reversal after DIF butterflies
    bit_reverse_permutation(a);

    // Combined normalize (1/N) and de-Montgomeryize in a single montmul.
    // montmul(val_mont, NINV_PLAIN) = val*R * (1/N) * R^{-1} = val/N (plain)
    let ninv_plain_v = if q_val == P7681 {
        _mm256_set1_epi16(NINV_PLAIN_7681)
    } else {
        _mm256_set1_epi16(NINV_PLAIN_10753)
    };
    let mut i = 0;
    while i + 16 <= N {
        let val = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let plain = montmul_x16(val, ninv_plain_v, qinv, qv);
        let plain = reduce_x16(plain, qv);
        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, plain);
        i += 16;
    }
    let ninv_plain = if q_val == P7681 {
        NINV_PLAIN_7681
    } else {
        NINV_PLAIN_10753
    };
    while i < N {
        let plain = montmul_scalar(a[i], ninv_plain, q_val);
        a[i] = mont_reduce(plain, q_val);
        i += 1;
    }
}

// -----------------------------------------------------------------------
// NEON NTT implementation (aarch64)
// -----------------------------------------------------------------------

#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn ntt512_neon(a: &mut [i16; N], twiddles: &[i16; LOG_N * (N / 2)], q_val: i64) {
    use core::arch::aarch64::*;

    bit_reverse_permutation(a);

    let qv = vdupq_n_s16(q_val as i16);
    let qinv = if q_val == P7681 {
        vdupq_n_s16(QINV_7681)
    } else {
        vdupq_n_s16(QINV_10753)
    };
    let ones = vdupq_n_s16(1);
    let qm1 = vsubq_s16(qv, ones);
    let neg_q = vnegq_s16(qv);

    for s in 0..LOG_N {
        let half_len = 1usize << s;
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        if half_len >= 8 {
            // Process 8 butterflies at a time
            for g in 0..num_groups {
                let mut j = 0;
                while j + 8 <= half_len {
                    let tw = vld1q_s16(twiddles.as_ptr().add(base + g * half_len + j));
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;

                    let u = vld1q_s16(a.as_ptr().add(idx0));
                    let v_raw = vld1q_s16(a.as_ptr().add(idx1));
                    let v = montmul_x8(v_raw, tw, qinv, qv);

                    let sum = vaddq_s16(u, v);
                    let diff = vsubq_s16(u, v);

                    // Signed reduction: (-2q, 2q) -> (-q, q)
                    let mask = vcgtq_s16(sum, qm1);
                    let sum = vsubq_s16(sum, vandq_s16(vreinterpretq_s16_u16(mask), qv));
                    let mask = vcgtq_s16(neg_q, sum);
                    let sum = vaddq_s16(sum, vandq_s16(vreinterpretq_s16_u16(mask), qv));

                    let mask = vcgtq_s16(diff, qm1);
                    let diff = vsubq_s16(diff, vandq_s16(vreinterpretq_s16_u16(mask), qv));
                    let mask = vcgtq_s16(neg_q, diff);
                    let diff = vaddq_s16(diff, vandq_s16(vreinterpretq_s16_u16(mask), qv));

                    vst1q_s16(a.as_mut_ptr().add(idx0), sum);
                    vst1q_s16(a.as_mut_ptr().add(idx1), diff);
                    j += 8;
                }
                // Scalar remainder
                let q32 = q_val as i32;
                while j < half_len {
                    let tw = twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = montmul_scalar(a[idx1], tw, q_val) as i32;
                    let mut s0 = u + v;
                    let mut s1 = u - v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    if s1 >= q32 {
                        s1 -= q32;
                    }
                    if s1 < -q32 {
                        s1 += q32;
                    }
                    a[idx0] = s0 as i16;
                    a[idx1] = s1 as i16;
                    j += 1;
                }
            }
        } else {
            // Small stages: use scalar
            let q32 = q_val as i32;
            for g in 0..num_groups {
                for j in 0..half_len {
                    let tw = twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = montmul_scalar(a[idx1], tw, q_val) as i32;
                    let mut s0 = u + v;
                    let mut s1 = u - v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    if s1 >= q32 {
                        s1 -= q32;
                    }
                    if s1 < -q32 {
                        s1 += q32;
                    }
                    a[idx0] = s0 as i16;
                    a[idx1] = s1 as i16;
                }
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn intt512_neon(
    a: &mut [i16; N],
    inv_twiddles: &[i16; LOG_N * (N / 2)],
    _ninv: i16,
    q_val: i64,
) {
    use core::arch::aarch64::*;

    let qv = vdupq_n_s16(q_val as i16);
    let qinv = if q_val == P7681 {
        vdupq_n_s16(QINV_7681)
    } else {
        vdupq_n_s16(QINV_10753)
    };
    let ones = vdupq_n_s16(1);
    let qm1 = vsubq_s16(qv, ones);
    let neg_q = vnegq_s16(qv);

    for s in 0..LOG_N {
        let half_len = 1 << (LOG_N - 1 - s);
        let num_groups = N / (2 * half_len);
        let base = s * (N / 2);

        if half_len >= 8 {
            for g in 0..num_groups {
                let mut j = 0;
                while j + 8 <= half_len {
                    let tw = vld1q_s16(inv_twiddles.as_ptr().add(base + g * half_len + j));
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;

                    let u = vld1q_s16(a.as_ptr().add(idx0));
                    let v = vld1q_s16(a.as_ptr().add(idx1));

                    // DIF butterfly: a' = u + v, b' = (u - v) * tw
                    let sum = vaddq_s16(u, v);
                    let diff = vsubq_s16(u, v);

                    // Reduce sum
                    let mask = vcgtq_s16(sum, qm1);
                    let sum = vsubq_s16(sum, vandq_s16(vreinterpretq_s16_u16(mask), qv));
                    let mask = vcgtq_s16(neg_q, sum);
                    let sum = vaddq_s16(sum, vandq_s16(vreinterpretq_s16_u16(mask), qv));

                    // Reduce diff before montmul
                    let mask = vcgtq_s16(diff, qm1);
                    let diff = vsubq_s16(diff, vandq_s16(vreinterpretq_s16_u16(mask), qv));
                    let mask = vcgtq_s16(neg_q, diff);
                    let diff = vaddq_s16(diff, vandq_s16(vreinterpretq_s16_u16(mask), qv));

                    vst1q_s16(a.as_mut_ptr().add(idx0), sum);
                    vst1q_s16(a.as_mut_ptr().add(idx1), montmul_x8(diff, tw, qinv, qv));
                    j += 8;
                }
                let q32 = q_val as i32;
                while j < half_len {
                    let tw = inv_twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = a[idx1] as i32;
                    let mut s0 = u + v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    a[idx0] = s0 as i16;
                    let mut d = u - v;
                    if d >= q32 {
                        d -= q32;
                    }
                    if d < -q32 {
                        d += q32;
                    }
                    a[idx1] = montmul_scalar(d as i16, tw, q_val);
                    j += 1;
                }
            }
        } else {
            let q32 = q_val as i32;
            for g in 0..num_groups {
                for j in 0..half_len {
                    let tw = inv_twiddles[base + g * half_len + j];
                    let idx0 = g * (2 * half_len) + j;
                    let idx1 = idx0 + half_len;
                    let u = a[idx0] as i32;
                    let v = a[idx1] as i32;
                    let mut s0 = u + v;
                    if s0 >= q32 {
                        s0 -= q32;
                    }
                    if s0 < -q32 {
                        s0 += q32;
                    }
                    a[idx0] = s0 as i16;
                    let mut d = u - v;
                    if d >= q32 {
                        d -= q32;
                    }
                    if d < -q32 {
                        d += q32;
                    }
                    a[idx1] = montmul_scalar(d as i16, tw, q_val);
                }
            }
        }
    }

    // Bit-reversal after DIF butterflies
    bit_reverse_permutation(a);

    // Combined normalize (1/N) and de-Montgomeryize
    let ninv_plain_v = if q_val == P7681 {
        vdupq_n_s16(NINV_PLAIN_7681)
    } else {
        vdupq_n_s16(NINV_PLAIN_10753)
    };
    let mut i = 0;
    while i + 8 <= N {
        let val = vld1q_s16(a.as_ptr().add(i));
        let plain = montmul_x8(val, ninv_plain_v, qinv, qv);
        let plain = reduce_x8(plain, qv);
        vst1q_s16(a.as_mut_ptr().add(i), plain);
        i += 8;
    }
    let ninv_plain = if q_val == P7681 {
        NINV_PLAIN_7681
    } else {
        NINV_PLAIN_10753
    };
    while i < N {
        let plain = montmul_scalar(a[i], ninv_plain, q_val);
        a[i] = mont_reduce(plain, q_val);
        i += 1;
    }
}

// -----------------------------------------------------------------------
// Good's permutation
// -----------------------------------------------------------------------

/// f(x) = f0(x^3) + x*f1(x^3) + x^2*f2(x^3)
/// fpad[k][j] = f[3*j + k] for k in 0..3, j in 0..256
pub(crate) fn good_permutation(fpad: &mut [[i16; N]; 3], f: &[i16], len: usize) {
    for k in 0..3 {
        fpad[k] = [0i16; N];
    }
    let n = len.min(768);
    for i in 0..n {
        fpad[i % 3][i / 3] = f[i];
    }
}

/// Inverse Good's: h[3*j + k] = hpad[k][j]
pub(crate) fn good_unpermutation(h: &mut [i16], hpad: &[[i16; N]; 3]) {
    for j in 0..N {
        for k in 0..3 {
            let idx = 3 * j + k;
            if idx < h.len() {
                h[idx] = hpad[k][j];
            }
        }
    }
}

// -----------------------------------------------------------------------
// CRT reconstruction
// -----------------------------------------------------------------------

const INV_7681_MOD_10753: i64 = mod_inverse(P7681, P10753);
const P1P2: i64 = P7681 * P10753;
const P1P2_HALF: i64 = P1P2 / 2;

/// Reconstruct from residues mod 7681 and mod 10753 to mod 4591.
/// Uses signed CRT: recovers the exact integer in [-p1*p2/2, p1*p2/2),
/// then reduces mod 4591.
#[inline(always)]
pub(crate) fn crt_reconstruct(a0: i16, a1: i16) -> i16 {
    let a0_64 = a0 as i64;
    let a1_64 = a1 as i64;
    let diff = ((a1_64 - a0_64) % P10753 + P10753) % P10753;
    let t = (diff * INV_7681_MOD_10753) % P10753;
    let mut x = a0_64 + P7681 * t;
    // Convert to signed representative: x in [-p1*p2/2, p1*p2/2)
    if x > P1P2_HALF {
        x -= P1P2;
    }
    // Now x is the exact integer value; reduce mod 4591
    let r = ((x % Q4591) + Q4591) % Q4591;
    r as i16
}

pub(crate) fn crt_reconstruct_array(out: &mut [i16], a7681: &[i16], a10753: &[i16], len: usize) {
    for i in 0..len {
        out[i] = crt_reconstruct(a7681[i], a10753[i]);
    }
}

// -----------------------------------------------------------------------
// Public NTT dispatch
// -----------------------------------------------------------------------

pub(crate) fn ntt512_forward_7681(a: &mut [i16; N]) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    unsafe {
        return ntt512_avx2(a, &TWIDDLE_7681, P7681);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    unsafe {
        return ntt512_neon(a, &TWIDDLE_7681, P7681);
    }
    #[allow(unreachable_code)]
    ntt512_scalar(a, &TWIDDLE_7681, P7681);
}

pub(crate) fn ntt512_forward_10753(a: &mut [i16; N]) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    unsafe {
        return ntt512_avx2(a, &TWIDDLE_10753, P10753);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    unsafe {
        return ntt512_neon(a, &TWIDDLE_10753, P10753);
    }
    #[allow(unreachable_code)]
    ntt512_scalar(a, &TWIDDLE_10753, P10753);
}

pub(crate) fn ntt512_inverse_7681(a: &mut [i16; N]) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    unsafe {
        return intt512_avx2(a, &INV_TWIDDLE_7681, NINV_MONT_7681, P7681);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    unsafe {
        return intt512_neon(a, &INV_TWIDDLE_7681, NINV_MONT_7681, P7681);
    }
    #[allow(unreachable_code)]
    intt512_scalar(a, &INV_TWIDDLE_7681, NINV_MONT_7681, P7681);
}

pub(crate) fn ntt512_inverse_10753(a: &mut [i16; N]) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    unsafe {
        return intt512_avx2(a, &INV_TWIDDLE_10753, NINV_MONT_10753, P10753);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    unsafe {
        return intt512_neon(a, &INV_TWIDDLE_10753, NINV_MONT_10753, P10753);
    }
    #[allow(unreachable_code)]
    intt512_scalar(a, &INV_TWIDDLE_10753, NINV_MONT_10753, P10753);
}

// -----------------------------------------------------------------------
// Full 768-point polynomial multiplication using NTT
// -----------------------------------------------------------------------

/// Multiply two polynomials f, g (each up to 768 coefficients) using NTT.
/// Result has up to 1535 coefficients, stored in h[0..1536].
/// All arithmetic is mod q_target (4591) for the final result.
pub(crate) fn mult768(h: &mut [i16; 1536], f: &[i16], f_len: usize, g: &[i16], g_len: usize) {
    // Step 1: Good's permutation -> 3 sub-polynomials of length <= 256
    let mut fpad = [[0i16; N]; 3];
    let mut gpad = [[0i16; N]; 3];
    good_permutation(&mut fpad, f, f_len);
    good_permutation(&mut gpad, g, g_len);

    // Step 2-5: NTT multiply for both primes and combine products

    // --- Mod 7681 ---
    let mut f7 = [[0i16; N]; 3];
    let mut g7 = [[0i16; N]; 3];
    for k in 0..3 {
        for j in 0..N {
            f7[k][j] = to_mont(fpad[k][j] as i64, P7681);
            g7[k][j] = to_mont(gpad[k][j] as i64, P7681);
        }
        ntt512_forward_7681(&mut f7[k]);
        ntt512_forward_7681(&mut g7[k]);
    }

    let mut h7 = [[0i16; N]; 5];
    pointwise_products(&mut h7, &f7, &g7, P7681);

    for k in 0..5 {
        ntt512_inverse_7681(&mut h7[k]);
    }

    // --- Mod 10753 ---
    let mut f10 = [[0i16; N]; 3];
    let mut g10 = [[0i16; N]; 3];
    for k in 0..3 {
        for j in 0..N {
            f10[k][j] = to_mont(fpad[k][j] as i64, P10753);
            g10[k][j] = to_mont(gpad[k][j] as i64, P10753);
        }
        ntt512_forward_10753(&mut f10[k]);
        ntt512_forward_10753(&mut g10[k]);
    }

    let mut h10 = [[0i16; N]; 5];
    pointwise_products(&mut h10, &f10, &g10, P10753);

    for k in 0..5 {
        ntt512_inverse_10753(&mut h10[k]);
    }

    // Step 6: CRT reconstruction and inverse Good's for the 5-component product
    *h = [0i16; 1536];

    for k in 0..5 {
        let outer = k % 3; // which sub-poly component
        let shift = k / 3; // 0 for k=0,1,2; 1 for k=3,4
        for j in 0..N {
            let c7 = h7[k][j];
            let c10 = h10[k][j];
            let c = crt_reconstruct(c7, c10);
            let idx = 3 * (j + shift) + outer;
            if idx < 1536 {
                let sum = h[idx] as i32 + c as i32;
                h[idx] = super::modq::freeze(sum);
            }
        }
    }
}

/// Compute 5 product components from 3x3 NTT products (pointwise in NTT domain).
/// d0 = f0*g0, d1 = f0*g1 + f1*g0, d2 = f0*g2 + f1*g1 + f2*g0,
/// d3 = f1*g2 + f2*g1, d4 = f2*g2
fn pointwise_products(h: &mut [[i16; N]; 5], f: &[[i16; N]; 3], g: &[[i16; N]; 3], q: i64) {
    let q32 = q as i32;
    for j in 0..N {
        let f0 = f[0][j];
        let f1 = f[1][j];
        let f2 = f[2][j];
        let g0 = g[0][j];
        let g1 = g[1][j];
        let g2 = g[2][j];

        h[0][j] = montmul_scalar(f0, g0, q);

        let mut s = montmul_scalar(f0, g1, q) as i32 + montmul_scalar(f1, g0, q) as i32;
        if s >= q32 {
            s -= q32;
        } else if s < -q32 {
            s += q32;
        }
        h[1][j] = s as i16;

        s = montmul_scalar(f0, g2, q) as i32
            + montmul_scalar(f1, g1, q) as i32
            + montmul_scalar(f2, g0, q) as i32;
        while s >= q32 {
            s -= q32;
        }
        while s < -q32 {
            s += q32;
        }
        h[2][j] = s as i16;

        s = montmul_scalar(f1, g2, q) as i32 + montmul_scalar(f2, g1, q) as i32;
        if s >= q32 {
            s -= q32;
        } else if s < -q32 {
            s += q32;
        }
        h[3][j] = s as i16;

        h[4][j] = montmul_scalar(f2, g2, q);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_roundtrip_7681() {
        // Test with plain values (not Montgomery form)
        let mut a = [0i16; N];
        for i in 0..20 {
            a[i] = to_mont((i as i64 + 1) % P7681, P7681);
        }
        // Remember the plain values
        let mut expected = [0i16; N];
        for i in 0..N {
            expected[i] = from_mont(a[i], P7681);
        }

        ntt512_forward_7681(&mut a);
        ntt512_inverse_7681(&mut a);
        // After intt, values are in plain form [0, q)

        for i in 0..N {
            assert_eq!(
                expected[i], a[i],
                "NTT roundtrip 7681 failed at index {i}: expected {}, got {}",
                expected[i], a[i]
            );
        }
    }

    #[test]
    fn test_ntt_roundtrip_10753() {
        let mut a = [0i16; N];
        for i in 0..20 {
            a[i] = to_mont((i as i64 + 1) % P10753, P10753);
        }
        let mut expected = [0i16; N];
        for i in 0..N {
            expected[i] = from_mont(a[i], P10753);
        }

        ntt512_forward_10753(&mut a);
        ntt512_inverse_10753(&mut a);

        for i in 0..N {
            assert_eq!(
                expected[i], a[i],
                "NTT roundtrip 10753 failed at index {i}: expected {}, got {}",
                expected[i], a[i]
            );
        }
    }

    #[test]
    fn test_crt_reconstruct() {
        for v in [0i64, 1, 100, 2295, 4590] {
            let a0 = (v % P7681) as i16;
            let a1 = (v % P10753) as i16;
            let result = crt_reconstruct(a0, a1);
            let expected = (v % Q4591) as i16;
            assert_eq!(result, expected, "CRT failed for v={v}");
        }
    }

    #[test]
    fn test_mult768_simple() {
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        f[0] = 1;
        f[1] = 1;
        g[0] = 1;
        g[1] = 1;

        let mut h = [0i16; 1536];
        mult768(&mut h, &f, 768, &g, 768);

        assert_eq!(h[0], 1, "h[0]");
        assert_eq!(h[1], 2, "h[1]");
        assert_eq!(h[2], 1, "h[2]");
        for i in 3..100 {
            assert_eq!(h[i], 0, "h[{i}] should be 0, got {}", h[i]);
        }
    }

    #[test]
    fn test_ntt_mult_two_sparse() {
        // Two sparse polynomials: f = [1, 0, 0, 2], g = [3, 0, 1]
        // Product: 3 + 0 + 1 + 6x + 0 + 2x^2 = [3, 0, 1, 6, 0, 2]
        // Actually: f*g = (1 + 2x^3)*(3 + x^2) = 3 + x^2 + 6x^3 + 2x^5
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        f[0] = 1;
        f[3] = 2;
        g[0] = 3;
        g[2] = 1;

        let mut h = [0i16; 1536];
        mult768(&mut h, &f, 768, &g, 768);

        assert_eq!(h[0], 3, "h[0]");
        assert_eq!(h[1], 0, "h[1]");
        assert_eq!(h[2], 1, "h[2]");
        assert_eq!(h[3], 6, "h[3]");
        assert_eq!(h[4], 0, "h[4]");
        assert_eq!(h[5], 2, "h[5]");
        assert_eq!(h[6], 0, "h[6]");
    }

    #[test]
    fn test_ntt_mult_single_large() {
        // f = [42], g = [17], h = [714]
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        f[0] = 42;
        g[0] = 17;
        let mut h = [0i16; 1536];
        mult768(&mut h, &f, 768, &g, 768);
        assert_eq!(h[0], 714, "42*17=714, got {}", h[0]);
        assert_eq!(h[1], 0);
    }

    fn normalize_4591(x: i16) -> i64 {
        ((x as i64 % 4591) + 4591) % 4591
    }

    #[test]
    fn test_ntt_mult_two_large() {
        // f = [42, 100], g = [17, 50]
        // h[0] = 42*17 = 714
        // h[1] = 42*50 + 100*17 = 2100 + 1700 = 3800
        // h[2] = 100*50 = 5000 mod 4591 = 409
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        f[0] = 42;
        f[1] = 100;
        g[0] = 17;
        g[1] = 50;
        let mut h = [0i16; 1536];
        mult768(&mut h, &f, 768, &g, 768);
        assert_eq!(normalize_4591(h[0]), 714, "h[0]");
        assert_eq!(normalize_4591(h[1]), 3800, "h[1]");
        assert_eq!(normalize_4591(h[2]), 409, "h[2]");
    }

    #[test]
    fn test_ntt_conv_direct() {
        // Compute convolution via NTT and compare with direct computation.
        // Use small 4-element polynomials.
        let f = [1i16, 10, 19, 28]; // f0, f1, f2, f3
        let g = [2i16, 23, 44, 65]; // g0, g1, g2, g3

        // Expected linear convolution (7 coefficients):
        let mut expected = [0i64; 7];
        for i in 0..4 {
            for j in 0..4 {
                expected[i + j] += f[i] as i64 * g[j] as i64;
            }
        }

        // Test via NTT-512 mod 7681
        let mut fa = [0i16; N];
        let mut ga = [0i16; N];
        for j in 0..4 {
            fa[j] = to_mont(f[j] as i64, P7681);
            ga[j] = to_mont(g[j] as i64, P7681);
        }
        ntt512_forward_7681(&mut fa);
        ntt512_forward_7681(&mut ga);

        // Pointwise multiply
        for j in 0..N {
            fa[j] = montmul_scalar(fa[j], ga[j], P7681);
        }
        ntt512_inverse_7681(&mut fa);

        for i in 0..7 {
            let e = expected[i] % P7681;
            let got = fa[i] as i64;
            assert_eq!(e, got, "NTT conv [{i}] mod 7681: expected {e}, got {got}");
        }
    }

    #[test]
    fn test_ntt_mult_matches_schoolbook() {
        // Use i64 schoolbook to avoid modular reduction issues
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        for i in 0..10 {
            f[i] = (i as i16 * 3 + 1) % 100;
            g[i] = (i as i16 * 7 + 2) % 100;
        }

        // Schoolbook using i64 to avoid mod issues
        let mut h_school = [0i64; 1536];
        for i in 0..768 {
            for j in 0..768 {
                h_school[i + j] += f[i] as i64 * g[j] as i64;
            }
        }

        // NTT
        let mut h_ntt = [0i16; 1536];
        mult768(&mut h_ntt, &f, 768, &g, 768);

        for i in 0..200 {
            let a = ((h_school[i] % 4591) + 4591) % 4591;
            let b = ((h_ntt[i] as i64 % 4591) + 4591) % 4591;
            assert_eq!(a, b, "Mismatch at index {i}: schoolbook={a}, ntt={b}");
        }
    }

    #[test]
    fn test_ntt512_conv_large() {
        // Test NTT-512 convolution with 254-degree polynomials (matching sub-poly size)
        let mut f = [0i16; N];
        let mut g = [0i16; N];
        for i in 0..254 {
            f[i] = ((i as i64 * 3 + 1) % 50) as i16;
            g[i] = ((i as i64 * 7 + 2) % 50) as i16;
        }

        // Schoolbook convolution using i64
        let mut expected = [0i64; 1024];
        for i in 0..254 {
            for j in 0..254 {
                expected[i + j] += f[i] as i64 * g[j] as i64;
            }
        }

        // NTT-512 convolution mod 7681
        let mut fa = [0i16; N];
        let mut ga = [0i16; N];
        for j in 0..N {
            fa[j] = to_mont(f[j] as i64, P7681);
            ga[j] = to_mont(g[j] as i64, P7681);
        }
        ntt512_forward_7681(&mut fa);
        ntt512_forward_7681(&mut ga);
        for j in 0..N {
            fa[j] = montmul_scalar(fa[j], ga[j], P7681);
        }
        ntt512_inverse_7681(&mut fa);

        for i in 0..507 {
            let e = ((expected[i] % P7681) + P7681) % P7681;
            let got = fa[i] as i64;
            assert_eq!(
                e, got,
                "Large NTT conv [{i}] mod 7681: expected {e}, got {got}"
            );
        }
    }

    /// Test Good's permutation + single-prime NTT pipeline (no CRT)
    #[test]
    fn test_goods_ntt_single_prime() {
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        for i in 0..crate::P {
            f[i] = ((i as i64 * 3 + 1) % 100) as i16;
            g[i] = ((i as i64 * 7 + 2) % 5 - 2) as i16;
        }

        // Good's permutation
        let mut fpad = [[0i16; N]; 3];
        let mut gpad = [[0i16; N]; 3];
        good_permutation(&mut fpad, &f, 768);
        good_permutation(&mut gpad, &g, 768);

        // NTT forward for one prime (7681)
        let mut f7 = [[0i16; N]; 3];
        let mut g7 = [[0i16; N]; 3];
        for k in 0..3 {
            for j in 0..N {
                f7[k][j] = to_mont(fpad[k][j] as i64, P7681);
                g7[k][j] = to_mont(gpad[k][j] as i64, P7681);
            }
            ntt512_forward_7681(&mut f7[k]);
            ntt512_forward_7681(&mut g7[k]);
        }

        // Pointwise products
        let mut h7 = [[0i16; N]; 5];
        pointwise_products(&mut h7, &f7, &g7, P7681);

        // Inverse NTT
        for k in 0..5 {
            ntt512_inverse_7681(&mut h7[k]);
        }

        // Unpermute and accumulate (single prime, no CRT)
        let mut h_ntt = [0i16; 1536];
        for k in 0..5 {
            let outer = k % 3;
            let shift = k / 3;
            for j in 0..N {
                let c = h7[k][j];
                let idx = 3 * (j + shift) + outer;
                if idx < 1536 {
                    let sum = h_ntt[idx] as i32 + c as i32;
                    // Reduce mod 7681
                    let mut r = sum % (P7681 as i32);
                    if r < 0 {
                        r += P7681 as i32;
                    }
                    h_ntt[idx] = r as i16;
                }
            }
        }

        // Schoolbook using i64
        let mut h_school = [0i64; 1536];
        for i in 0..768 {
            for j in 0..768 {
                h_school[i + j] += f[i] as i64 * g[j] as i64;
            }
        }

        // Compare first few indices mod 7681
        for i in 0..20 {
            let a = ((h_school[i] % P7681) + P7681) % P7681;
            let b = h_ntt[i] as i64;
            assert_eq!(
                a, b,
                "Single-prime mismatch at index {i}: schoolbook={a}, ntt={b}"
            );
        }
    }

    #[test]
    fn test_ntt_mult_full_size() {
        // Full P=761 element polynomials to match actual sntrup761 usage
        let mut f = [0i16; 768];
        let mut g = [0i16; 768];
        for i in 0..crate::P {
            f[i] = ((i as i64 * 3 + 1) % 100) as i16;
            g[i] = ((i as i64 * 7 + 2) % 5 - 2) as i16;
        }

        // Schoolbook using i64
        let mut h_school = [0i64; 1536];
        for i in 0..768 {
            for j in 0..768 {
                h_school[i + j] += f[i] as i64 * g[j] as i64;
            }
        }

        // NTT
        let mut h_ntt = [0i16; 1536];
        mult768(&mut h_ntt, &f, 768, &g, 768);

        for i in 0..1521 {
            let a = ((h_school[i] % 4591) + 4591) % 4591;
            let b = ((h_ntt[i] as i64 % 4591) + 4591) % 4591;
            assert_eq!(
                a, b,
                "Full-size mismatch at index {i}: schoolbook={a}, ntt={b}"
            );
        }
    }
}
