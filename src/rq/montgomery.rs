#![allow(
    dead_code,
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Montgomery modular arithmetic for i16 NTT computations.
//!
//! Convention (same as Kyber/Dilithium):
//! - R = 2^16
//! - QINV = q^{-1} mod R (stored as i16, wraps for values > 32767)
//! - Montgomery form of a: aR mod q
//! - Montgomery product: montprod(aR, bR) = abR mod q
//! - Formula: T = a*b; u = (T mod R) * QINV mod R; result = (T - u*q) / R
//!
//! The SIMD version uses:
//!   t_lo = mullo(a, b);  t_hi = mulhi(a, b);
//!   u = mullo(t_lo, qinv);  result = t_hi - mulhi(u, q)

/// Compute modular inverse using extended Euclidean algorithm.
/// Returns x such that a*x ≡ 1 (mod m), or 0 if gcd(a,m) != 1.
pub(crate) const fn mod_inverse(a: i64, m: i64) -> i64 {
    let mut old_r = a;
    let mut r = m;
    let mut old_s: i64 = 1;
    let mut s: i64 = 0;

    while r != 0 {
        let q = old_r / r;
        let tmp_r = r;
        r = old_r - q * r;
        old_r = tmp_r;
        let tmp_s = s;
        s = old_s - q * s;
        old_s = tmp_s;
    }

    if old_r < 0 {
        old_s = -old_s;
    }

    ((old_s % m) + m) % m
}

/// Compute a^exp mod m using binary exponentiation.
pub(crate) const fn mod_pow(mut base: i64, mut exp: i64, m: i64) -> i64 {
    let mut result: i64 = 1;
    base %= m;
    if base < 0 {
        base += m;
    }
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % m;
        }
        exp >>= 1;
        base = (base * base) % m;
    }
    result
}

/// Find a primitive root (generator) of Z_p* for prime p.
pub(crate) const fn find_generator(p: i64) -> i64 {
    let pm1 = p - 1;
    let mut g: i64 = 2;
    while g < p {
        let mut is_gen = true;
        // Check prime factors 2, 3, 5, 7 (covers both 7680 and 10752)
        let factors = [2i64, 3, 5, 7];
        let mut fi = 0;
        while fi < 4 {
            let f = factors[fi];
            if pm1 % f == 0 && mod_pow(g, pm1 / f, p) == 1 {
                is_gen = false;
                break;
            }
            fi += 1;
        }
        if is_gen {
            return g;
        }
        g += 1;
    }
    0
}

/// NTT prime 7681 = 15 * 512 + 1
pub(crate) const P7681: i64 = 7681;
/// NTT prime 10753 = 21 * 512 + 1
pub(crate) const P10753: i64 = 10753;
/// Target prime for sntrup761
pub(crate) const Q4591: i64 = 4591;

/// Montgomery R = 2^16
pub(crate) const R: i64 = 65536;

/// q^{-1} mod R for q=7681 (positive inverse, stored as i16)
pub(crate) const QINV_7681: i16 = compute_qinv(P7681);
/// q^{-1} mod R for q=10753
pub(crate) const QINV_10753: i16 = compute_qinv(P10753);
/// q^{-1} mod R for q=4591
pub(crate) const QINV_4591: i16 = compute_qinv(Q4591);

/// Compute q^{-1} mod 2^16 as i16 (positive inverse; wraps for values > 32767)
const fn compute_qinv(q: i64) -> i16 {
    let qinv = mod_inverse(q, R);
    qinv as i16
}

/// Convert to Montgomery form: a -> aR mod q
pub(crate) const fn to_mont(a: i64, q: i64) -> i16 {
    let a_mod = ((a % q) + q) % q;
    let r_mod = R % q;
    ((a_mod * r_mod) % q) as i16
}

/// Convert from Montgomery form: aR -> a mod q
/// Uses Montgomery reduction with T = a (treating a as a 1*R-scaled value).
pub(crate) const fn from_mont(a: i16, q: i64) -> i16 {
    // Montgomery reduce: input is a (which represents a*R mod q),
    // we want to compute a * R^{-1} mod q.
    // T = a (as i32), then standard reduction.
    let qinv = mod_inverse(q, R);
    let a32 = a as i32;
    let q32 = q as i32;
    // u = (T mod R) * qinv mod R
    let u = (a32 as i16 as i32).wrapping_mul(qinv as i32) as i16;
    // result = (T - u * q) >> 16
    let r = (a32 - (u as i32) * q32) >> 16;
    // The result may be in [-q, q), reduce to [0, q)
    if r < 0 { (r + q32) as i16 } else { r as i16 }
}

/// Primitive 512th root of unity mod q (NOT in Montgomery form).
pub(crate) const fn primitive_root_512(q: i64) -> i64 {
    let g = find_generator(q);
    mod_pow(g, (q - 1) / 512, q)
}

/// Montgomery multiplication (SIMD, 16 elements): a*b*R^{-1} mod q
///
/// qinv_vec = broadcast(q^{-1} mod R), q_vec = broadcast(q)
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[inline(always)]
pub(crate) unsafe fn montmul_x16(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
    qinv: core::arch::x86_64::__m256i,
    q: core::arch::x86_64::__m256i,
) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    let t_lo = _mm256_mullo_epi16(a, b);
    let t_hi = _mm256_mulhi_epi16(a, b);
    let u = _mm256_mullo_epi16(t_lo, qinv);
    _mm256_sub_epi16(t_hi, _mm256_mulhi_epi16(u, q))
}

/// Reduce a value in [-q, q) to [0, q) range.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[inline(always)]
pub(crate) unsafe fn reduce_x16(
    a: core::arch::x86_64::__m256i,
    q: core::arch::x86_64::__m256i,
) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    let mask = _mm256_srai_epi16(a, 15); // all 1s if negative
    _mm256_add_epi16(a, _mm256_and_si256(mask, q))
}

/// Add two values modulo q, assuming inputs in [0, q).
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[inline(always)]
pub(crate) unsafe fn addmod_x16(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
    q: core::arch::x86_64::__m256i,
) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    let sum = _mm256_add_epi16(a, b);
    let t = _mm256_sub_epi16(sum, q);
    // If t < 0, sum was < q, so use sum; else use t
    let mask = _mm256_srai_epi16(t, 15);
    _mm256_add_epi16(t, _mm256_and_si256(mask, q))
}

/// Subtract two values modulo q, assuming inputs in [0, q).
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[inline(always)]
pub(crate) unsafe fn submod_x16(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
    q: core::arch::x86_64::__m256i,
) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    let diff = _mm256_sub_epi16(a, b);
    let mask = _mm256_srai_epi16(diff, 15);
    _mm256_add_epi16(diff, _mm256_and_si256(mask, q))
}

// -----------------------------------------------------------------------
// NEON (aarch64) SIMD helpers — 8 elements at a time
// -----------------------------------------------------------------------

/// Emulate `_mm256_mulhi_epi16`: signed 16×16→32 high-half for 8 lanes.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
pub(crate) unsafe fn mulhi_s16(
    a: core::arch::aarch64::int16x8_t,
    b: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        // Multiply low and high halves → i32, then take high 16 bits
        let lo32 = vmull_s16(vget_low_s16(a), vget_low_s16(b));
        let hi32 = vmull_high_s16(a, b);
        vcombine_s16(vshrn_n_s32(lo32, 16), vshrn_n_s32(hi32, 16))
    }
}

/// Montgomery multiplication (SIMD, 8 elements): a*b*R^{-1} mod q
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
pub(crate) unsafe fn montmul_x8(
    a: core::arch::aarch64::int16x8_t,
    b: core::arch::aarch64::int16x8_t,
    qinv: core::arch::aarch64::int16x8_t,
    q: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        let t_lo = vmulq_s16(a, b);
        let t_hi = mulhi_s16(a, b);
        let u = vmulq_s16(t_lo, qinv);
        vsubq_s16(t_hi, mulhi_s16(u, q))
    }
}

/// Reduce a value in [-q, q) to [0, q) range.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
pub(crate) unsafe fn reduce_x8(
    a: core::arch::aarch64::int16x8_t,
    q: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        let mask = vshrq_n_s16(a, 15); // all 1s if negative
        vaddq_s16(a, vandq_s16(mask, q))
    }
}

/// Add two values modulo q, assuming inputs in [0, q).
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
pub(crate) unsafe fn addmod_x8(
    a: core::arch::aarch64::int16x8_t,
    b: core::arch::aarch64::int16x8_t,
    q: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        let sum = vaddq_s16(a, b);
        let t = vsubq_s16(sum, q);
        let mask = vshrq_n_s16(t, 15);
        vaddq_s16(t, vandq_s16(mask, q))
    }
}

/// Subtract two values modulo q, assuming inputs in [0, q).
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
pub(crate) unsafe fn submod_x8(
    a: core::arch::aarch64::int16x8_t,
    b: core::arch::aarch64::int16x8_t,
    q: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        let diff = vsubq_s16(a, b);
        let mask = vshrq_n_s16(diff, 15);
        vaddq_s16(diff, vandq_s16(mask, q))
    }
}

/// Scalar Montgomery multiplication: computes a*b*R^{-1} mod q.
/// Result is in range (-q, q).
#[inline(always)]
pub(crate) const fn montmul_scalar(a: i16, b: i16, q: i64) -> i16 {
    let qinv = compute_qinv(q) as i32;
    let a32 = a as i32;
    let b32 = b as i32;
    let q32 = q as i32;

    let t = a32 * b32;
    let u = ((t as i16) as i32).wrapping_mul(qinv) as i16;
    let r = (t - (u as i32) * q32) >> 16;
    r as i16
}

/// Scalar Montgomery reduction to [0, q).
#[inline(always)]
pub(crate) const fn mont_reduce(a: i16, q: i64) -> i16 {
    if a < 0 {
        (a as i32 + q as i32) as i16
    } else if a as i64 >= q {
        (a as i32 - q as i32) as i16
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inverse() {
        let inv = mod_inverse(P7681, R);
        assert_eq!((P7681 * inv) % R, 1);
        let inv = mod_inverse(P10753, R);
        assert_eq!((P10753 * inv) % R, 1);
    }

    #[test]
    fn test_qinv() {
        // Verify: q * QINV ≡ 1 (mod R)
        let qinv7681 = QINV_7681 as u16 as u64;
        assert_eq!((P7681 as u64 * qinv7681) % (R as u64), 1);

        let qinv10753 = QINV_10753 as u16 as u64;
        assert_eq!((P10753 as u64 * qinv10753) % (R as u64), 1);
    }

    #[test]
    fn test_primitive_root() {
        let omega7681 = primitive_root_512(P7681);
        assert_eq!(mod_pow(omega7681, 512, P7681), 1);
        assert_ne!(mod_pow(omega7681, 256, P7681), 1);

        let omega10753 = primitive_root_512(P10753);
        assert_eq!(mod_pow(omega10753, 512, P10753), 1);
        assert_ne!(mod_pow(omega10753, 256, P10753), 1);
    }

    #[test]
    fn test_montgomery_roundtrip() {
        for a in [-100i64, -1, 0, 1, 42, 100, 3000] {
            let a_mont = to_mont(a, P7681);
            let a_back = from_mont(a_mont, P7681);
            let expected = ((a % P7681) + P7681) % P7681;
            assert_eq!(
                a_back as i64, expected,
                "Montgomery roundtrip failed for a={a}"
            );
        }
    }

    #[test]
    fn test_montmul_scalar() {
        for &(a, b) in &[(3i64, 5i64), (100, 200), (7680, 7680), (1, 0), (0, 0)] {
            let a_mont = to_mont(a, P7681);
            let b_mont = to_mont(b, P7681);
            let c_mont = montmul_scalar(a_mont, b_mont, P7681);
            let c = from_mont(mont_reduce(c_mont, P7681), P7681);
            let expected = ((a % P7681 * (b % P7681)) % P7681 + P7681) % P7681;
            assert_eq!(
                c as i64, expected,
                "montmul_scalar({a}, {b}) mod 7681 failed: a_mont={a_mont}, b_mont={b_mont}, c_mont={c_mont}, c={c}"
            );
        }
    }

    #[test]
    fn test_montmul_scalar_10753() {
        for &(a, b) in &[(3i64, 5i64), (100, 200), (10752, 10752), (1, 0)] {
            let a_mont = to_mont(a, P10753);
            let b_mont = to_mont(b, P10753);
            let c_mont = montmul_scalar(a_mont, b_mont, P10753);
            let c = from_mont(mont_reduce(c_mont, P10753), P10753);
            let expected = ((a % P10753 * (b % P10753)) % P10753 + P10753) % P10753;
            assert_eq!(
                c as i64, expected,
                "montmul_scalar({a}, {b}) mod 10753 failed"
            );
        }
    }

    #[test]
    fn test_generator() {
        let g7681 = find_generator(P7681);
        assert!(g7681 > 0);
        assert_eq!(mod_pow(g7681, P7681 - 1, P7681), 1);
        assert_eq!(mod_pow(g7681, (P7681 - 1) / 2, P7681), P7681 - 1);

        let g10753 = find_generator(P10753);
        assert!(g10753 > 0);
        assert_eq!(mod_pow(g10753, P10753 - 1, P10753), 1);
    }
}
