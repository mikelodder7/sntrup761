pub mod mod3;
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
        vector::minus_product(&mut g, P + 1, &f, c);
        vector::shift(&mut g, P + 1);
        vector::minus_product(&mut v, LOOPS + 1, &u, c);
        vector::shift(&mut v, LOOPS + 1);
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

pub fn mult(h: &mut [i8; P], f: [i8; P], g: [i8; P]) {
    let mut fg = [0i8; P * 2 - 1];
    for i in 0..P {
        let mut r = 0i8;
        for j in 0..=i {
            r = mod3::plus_product(r, f[j], g[i - j]);
        }
        fg[i] = r;
    }
    for i in P..(P * 2 - 1) {
        let mut r = 0i8;
        for j in (i - P + 1)..P {
            r = mod3::plus_product(r, f[j], g[i - j])
        }
        fg[i] = r;
    }
    for i in (P..(P * 2) - 1).rev() {
        let tmp1 = mod3::sum(fg[i - P], fg[i]);
        fg[i - P] = tmp1;
        let tmp2 = mod3::sum(fg[i - P + 1], fg[i]);
        fg[i - P + 1] = tmp2;
    }

    h[..P].clone_from_slice(&fg[..P]);
}
