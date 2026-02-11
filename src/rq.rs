pub mod encoding;
pub mod modq;
mod vector;

use crate::P;

fn swap_int(x: isize, y: isize, mask: isize) -> (isize, isize) {
    let t = mask & (x ^ y);
    (x ^ t, y ^ t)
}

fn smaller_mask(x: isize, y: isize) -> isize {
    (x - y) >> 31
}

#[allow(clippy::cast_possible_wrap)]
pub fn reciprocal3(s: [i8; P]) -> [i16; P] {
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
        vector::minus_product(&mut g, P + 1, &f, c);
        vector::shift(&mut g, P + 1);
        vector::minus_product(&mut v, LOOPS + 1, &u, c);
        vector::shift(&mut v, LOOPS + 1);
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

#[allow(clippy::cast_possible_truncation)]
pub fn round3(h: &mut [i16; P]) {
    let f: [i16; P] = *h;
    for i in 0..P {
        let inner = 21846i32 * (f[i] + 2295) as i32;
        h[i] = (((inner + 32768) >> 16) * 3 - 2295) as i16;
    }
}

pub fn mult(h: &mut [i16; P], f: [i16; P], g: [i8; P]) {
    let mut fg = [0i16; P * 2 - 1];
    for i in 0..P {
        let mut r = 0i16;
        for j in 0..=i {
            r = modq::plus_product(r, f[j], g[i - j] as i16);
        }
        fg[i] = r;
    }
    for i in P..(P * 2 - 1) {
        let mut r = 0i16;
        for j in (i - P + 1)..P {
            r = modq::plus_product(r, f[j], g[i - j] as i16)
        }
        fg[i] = r;
    }
    for i in (P..(P * 2) - 1).rev() {
        fg[i - P] = modq::sum(fg[i - P], fg[i]);
        fg[i - P + 1] = modq::sum(fg[i - P + 1], fg[i]);
    }
    h[..P].clone_from_slice(&fg[..P]);
}
