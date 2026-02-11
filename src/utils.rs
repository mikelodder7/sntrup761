use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::{
    r3, rq, zx, Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret, CIPHERTEXT_SIZE, P,
    PUBLIC_KEY_SIZE, ROUNDED_ENCODE_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE, SMALL_ENCODE_SIZE,
    W,
};

/// Hash prefix helper: SHA-512(prefix || input), truncated to 32 bytes.
pub(crate) fn hash_prefix(out: &mut [u8; 32], prefix: u8, input: &[u8]) {
    let mut hasher = Sha512::new();
    hasher.update([prefix]);
    hasher.update(input);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
}

/// hash_confirm: Hash(2 || Hash(3 || r_enc) || cache)
/// where cache = Hash4(pk) stored in the secret key.
pub(crate) fn hash_confirm(out: &mut [u8; 32], r_enc: &[u8], cache: &[u8; 32]) {
    let mut inner = [0u8; 32];
    hash_prefix(&mut inner, 3, r_enc);

    let mut hasher = Sha512::new();
    hasher.update([2u8]);
    hasher.update(inner);
    hasher.update(&cache[..]);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
}

/// hash_session: Hash(b || Hash(3 || y) || z)
pub(crate) fn hash_session(out: &mut [u8; 32], b: u8, y: &[u8], z: &[u8]) {
    let mut inner = [0u8; 32];
    hash_prefix(&mut inner, 3, y);

    let mut hasher = Sha512::new();
    hasher.update([b]);
    hasher.update(inner);
    hasher.update(z);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn decapsulate_inner(
    cstr: &[u8; CIPHERTEXT_SIZE],
    sk: &[u8; SECRET_KEY_SIZE],
) -> [u8; SHARED_SECRET_SIZE] {
    // Parse SK: f(191) || ginv(191) || pk(1158) || rho(191) || cache(32)
    let mut f = zx::encoding::decode(&sk[..SMALL_ENCODE_SIZE]);
    let mut ginv = zx::encoding::decode(&sk[SMALL_ENCODE_SIZE..(2 * SMALL_ENCODE_SIZE)]);
    let pk_start = 2 * SMALL_ENCODE_SIZE;
    let pk_end = pk_start + PUBLIC_KEY_SIZE;
    let rho_start = pk_end;
    let rho_end = rho_start + SMALL_ENCODE_SIZE;
    let cache_start = rho_end;

    let mut cache = [0u8; 32];
    cache.copy_from_slice(&sk[cache_start..cache_start + 32]);

    // Decrypt: Rounded_decode, multiply by f, Rq_mult3, R3_fromRq, R3_mult by ginv
    let c = rq::encoding::rounded_decode(&cstr[..ROUNDED_ENCODE_SIZE]);
    let mut cf = [0i16; P];
    rq::mult(&mut cf, c, f);
    let mut t3 = [0i8; P];
    for i in 0..P {
        t3[i] = r3::mod3::freeze(rq::modq::freeze(3 * cf[i] as i32) as i32);
    }
    let mut r = [0i8; P];
    r3::mult(&mut r, t3, ginv);

    // Weight mask: on failure, set r to default weight-W vector
    // (W ones followed by P-W zeros), matching PQClean's Decrypt
    let w_mask = weightw_mask(&r);
    let not_mask = (!w_mask) as i8;
    for val in r[..W].iter_mut() {
        *val = ((*val ^ 1) & not_mask) ^ 1;
    }
    for val in r[W..P].iter_mut() {
        *val &= not_mask;
    }

    // Hide: encode r, re-encrypt with pk, compute confirm hash
    let mut r_enc = zx::encoding::encode(r);
    let h = rq::encoding::rq_decode(&sk[pk_start..pk_end]);
    let mut hr = [0i16; P];
    rq::mult(&mut hr, h, r);
    rq::round3(&mut hr);
    let mut cnew = [0u8; CIPHERTEXT_SIZE];
    cnew[..ROUNDED_ENCODE_SIZE].copy_from_slice(&rq::encoding::rounded_encode(&hr));
    let mut confirm = [0u8; 32];
    hash_confirm(&mut confirm, &r_enc, &cache);
    cnew[ROUNDED_ENCODE_SIZE..].copy_from_slice(&confirm);

    // Compare full ciphertexts (rounded + confirm hash)
    let mask = ciphertexts_diff_mask(cstr, &cnew);

    // Constant-time select: r_enc on success (mask=0), rho on failure (mask=-1)
    let rho = &sk[rho_start..rho_end];
    let mut selected = [0u8; SMALL_ENCODE_SIZE];
    selected.copy_from_slice(&r_enc);
    let mask_byte = mask as u8;
    for i in 0..SMALL_ENCODE_SIZE {
        selected[i] ^= mask_byte & (selected[i] ^ rho[i]);
    }

    // Hash session: prefix=1 on success (mask=0), prefix=0 on failure (mask=-1)
    let prefix = (1 + mask) as u8;
    let mut k = [0u8; SHARED_SECRET_SIZE];
    hash_session(&mut k, prefix, &selected, cstr);

    // Zeroize secret intermediates
    f.zeroize();
    ginv.zeroize();
    cache.zeroize();
    cf.zeroize();
    t3.zeroize();
    r.zeroize();
    r_enc.zeroize();
    hr.zeroize();
    cnew.zeroize();
    confirm.zeroize();
    selected.zeroize();

    k
}

/// Constant-time check if weight of r equals W.
/// Returns 0 if weight == W, -1 otherwise.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn weightw_mask(r: &[i8; P]) -> i32 {
    let mut weight: i32 = 0;
    for &val in r.iter() {
        weight += (val & 1) as i32;
    }
    int16_nonzero_mask((weight - W as i32) as i16)
}

/// Constant-time: returns 0 if x == 0, -1 (0xFFFFFFFF) otherwise.
#[allow(clippy::cast_sign_loss)]
fn int16_nonzero_mask(x: i16) -> i32 {
    let u = x as u16;
    let mut r = u.wrapping_neg() | u;
    r >>= 15;
    -(r as i32)
}

/// Constant-time comparison of two byte slices.
/// Returns 0 if equal, -1 otherwise.
#[allow(clippy::cast_possible_wrap)]
fn ciphertexts_diff_mask(a: &[u8], b: &[u8]) -> i32 {
    let mut diff: u16 = 0;
    let len = a.len().min(b.len());
    for i in 0..len {
        diff |= (a[i] ^ b[i]) as u16;
    }
    int16_nonzero_mask(diff as i16)
}

pub(crate) fn derive_key(
    f: [i8; P],
    g: [i8; P],
    gr: [i8; P],
    rho: [u8; SMALL_ENCODE_SIZE],
) -> (EncapsulationKey, DecapsulationKey) {
    let mut f3r = rq::reciprocal3(f);
    let mut h = [0i16; P];
    rq::mult(&mut h, f3r, g);
    let pk = rq::encoding::rq_encode(&h);

    // SK layout: f(191) || ginv(191) || pk(1158) || rho(191) || Hash4(pk)(32)
    let mut sk = [0u8; SECRET_KEY_SIZE];
    let mut f_enc = zx::encoding::encode(f);
    let mut ginv_enc = zx::encoding::encode(gr);

    sk[..SMALL_ENCODE_SIZE].copy_from_slice(&f_enc);
    sk[SMALL_ENCODE_SIZE..(2 * SMALL_ENCODE_SIZE)].copy_from_slice(&ginv_enc);
    sk[(2 * SMALL_ENCODE_SIZE)..(2 * SMALL_ENCODE_SIZE + PUBLIC_KEY_SIZE)].copy_from_slice(&pk);
    sk[(2 * SMALL_ENCODE_SIZE + PUBLIC_KEY_SIZE)
        ..(2 * SMALL_ENCODE_SIZE + PUBLIC_KEY_SIZE + SMALL_ENCODE_SIZE)]
        .copy_from_slice(&rho);

    // Hash4(pk) = Hash(4 || pk) truncated to 32 bytes
    let mut cache = [0u8; 32];
    hash_prefix(&mut cache, 4, &pk);
    sk[(2 * SMALL_ENCODE_SIZE + PUBLIC_KEY_SIZE + SMALL_ENCODE_SIZE)..].copy_from_slice(&cache);

    // Zeroize secret intermediates
    f3r.zeroize();
    h.zeroize();
    f_enc.zeroize();
    ginv_enc.zeroize();
    cache.zeroize();

    (EncapsulationKey(pk), DecapsulationKey(sk))
}

pub(crate) fn create_cipher(
    mut r: [i8; P],
    pk: &[u8; PUBLIC_KEY_SIZE],
) -> (Ciphertext, SharedSecret) {
    let h = rq::encoding::rq_decode(pk);
    let mut c = [0i16; P];
    rq::mult(&mut c, h, r);
    rq::round3(&mut c);

    let mut r_enc = zx::encoding::encode(r);

    // Compute confirm hash: Hash(2 || Hash(3 || r_enc) || Hash4(pk))
    let mut cache = [0u8; 32];
    hash_prefix(&mut cache, 4, pk);
    let mut confirm = [0u8; 32];
    hash_confirm(&mut confirm, &r_enc, &cache);

    // Ciphertext layout: rounded(1007) || confirm_hash(32)
    let mut cstr = [0u8; CIPHERTEXT_SIZE];
    cstr[..ROUNDED_ENCODE_SIZE].copy_from_slice(&rq::encoding::rounded_encode(&c));
    cstr[ROUNDED_ENCODE_SIZE..].copy_from_slice(&confirm);

    // Shared key: hash_session(1, r_enc, cstr)
    let mut k = [0u8; SHARED_SECRET_SIZE];
    hash_session(&mut k, 1, &r_enc, &cstr);

    // Zeroize secret intermediates
    r.zeroize();
    r_enc.zeroize();
    cache.zeroize();
    confirm.zeroize();

    (Ciphertext(cstr), SharedSecret(k))
}
