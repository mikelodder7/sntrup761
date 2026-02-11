pub mod encoding {
    use crate::{P, SMALL_ENCODE_SIZE};

    #[allow(clippy::cast_sign_loss)]
    pub fn encode(f: [i8; P]) -> [u8; SMALL_ENCODE_SIZE] {
        let mut c = [0u8; SMALL_ENCODE_SIZE];
        for (byte, chunk) in c[..SMALL_ENCODE_SIZE - 1].iter_mut().zip(f.chunks(4)) {
            let mut c0 = chunk[0] + 1;
            c0 += (chunk[1] + 1) << 2;
            c0 += (chunk[2] + 1) << 4;
            c0 += (chunk[3] + 1) << 6;
            *byte = c0 as u8;
        }
        c[SMALL_ENCODE_SIZE - 1] = (f[P - 1] + 1) as u8;
        c
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn decode(c: &[u8]) -> [i8; P] {
        let mut f = [0i8; P];
        for (byte, chunk) in c[..SMALL_ENCODE_SIZE - 1].iter().zip(f.chunks_mut(4)) {
            let mut c0 = *byte;
            chunk[0] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            chunk[1] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            chunk[2] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            chunk[3] = ((c0 & 3) as i8) - 1;
        }
        f[P - 1] = ((c[SMALL_ENCODE_SIZE - 1] & 3) as i8) - 1;
        f
    }
}

pub mod random {
    use crate::{P, W};
    use rand::Rng;
    use rand::RngExt;

    /// Branchless constant-time min/max swap (djbsort int32_minmax).
    /// Operates on a slice with two indices to avoid borrow issues.
    #[allow(clippy::cast_possible_truncation)]
    fn int32_minmax(x: &mut [i32], i: usize, j: usize) {
        let ab = x[j] ^ x[i];
        let mut c = (x[j] as i64) - (x[i] as i64);
        c ^= (ab as i64) & (c ^ (x[j] as i64));
        c >>= 31;
        c &= ab as i64;
        let c = c as i32;
        x[i] ^= c;
        x[j] ^= c;
    }

    pub fn sort(x: &mut [i32], n: usize) {
        if n < 2 {
            return;
        }
        let mut top = 1;
        while top < (n - top) {
            top += top;
        }
        let mut p = top;
        while p > 0 {
            for i in 0..(n - p) {
                if i & p == 0 {
                    int32_minmax(x, i, i + p);
                }
            }
            let mut q = top;
            while q > p {
                for i in 0..(n - q) {
                    if i & p == 0 {
                        int32_minmax(x, i + p, i + q);
                    }
                }
                q >>= 1;
            }
            p >>= 1;
        }
    }

    #[allow(clippy::cast_sign_loss)]
    pub fn random_small(g: &mut [i8; P], rng: &mut impl Rng) {
        for val in g.iter_mut() {
            let r: i32 = rng.random();
            *val = ((((1_073_741_823 & (r as u32)) * 3) >> 30) as i8) - 1;
        }
    }

    /// Unsigned sort: XOR with 0x80000000, signed sort, XOR back.
    /// Matches PQClean's crypto_sort_uint32.
    #[allow(clippy::cast_possible_wrap)]
    fn sort_uint32(x: &mut [i32], n: usize) {
        for val in x.iter_mut().take(n) {
            *val ^= 0x80000000u32 as i32;
        }
        sort(x, n);
        for val in x.iter_mut().take(n) {
            *val ^= 0x80000000u32 as i32;
        }
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn random_tsmall(f: &mut [i8; P], rng: &mut impl Rng) {
        let mut r = [0i32; P];
        for val in r.iter_mut() {
            *val = rng.random();
        }
        for val in r[..W].iter_mut() {
            *val &= -2;
        }
        for val in r[W..P].iter_mut() {
            *val = (*val & -3) | 1
        }
        sort_uint32(&mut r, P);
        for (fv, &rv) in f.iter_mut().zip(r.iter()) {
            *fv = ((rv & 3) as i8) - 1;
        }
    }
}
