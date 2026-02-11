//! # sntrup761
//!
//! This crate provides a pure-Rust implementation of the [Streamlined NTRU Prime 761](https://ntruprime.cr.yp.to/) post-quantum key encapsulation mechanism (KEM).
//! Streamlined NTRU Prime is a lattice-based, quantum-resistant cryptographic algorithm designed for secure key exchange and public-key encryption.
//!
//! ## Features
//! - Pure Rust, `no_std`-compatible, and dependency-minimal
//! - Implements the [NTRU Prime](https://ntruprime.cr.yp.to/) `sntrup761` parameter set (as submitted for standardization to NIST)
//! - Simple API for key generation, encapsulation, and decapsulation
//! - Zeroizes secret key material on drop
//! - Optional Serde support for key and ciphertext serialization (`serde` feature)
//!
//! ## Algorithm and References
//! - [NTRU Prime: Stronger and Simpler Public Key Cryptography](https://ntruprime.cr.yp.to/nist/ntruprime-20160525.pdf), by D.J. Bernstein, Ch. Chuengsatiansup, T. Lange, and C. van Vredendaal
//! - [NTRUEncrypt Algorithm Description](https://en.wikipedia.org/wiki/NTRUEncrypt)
//! - [sntrup761 official specification](https://ntruprime.cr.yp.to/sntrup761.html)
//! - [PQClean reference implementation (C)](https://github.com/PQClean/PQClean/tree/master/crypto_kem/sntrup761)
//!
//! ## Example Usage
//!
//! ```rust
//! use sntrup761::*;
//!
//! // Key generation
//! let (pk, sk) = generate_key(rand::rng());
//!
//! // Key encapsulation
//! let (ct, ss_sender) = pk.encapsulate(rand::rng());
//!
//! // Key decapsulation
//! let ss_receiver = sk.decapsulate(&ct);
//!
//! assert!(ss_sender == ss_receiver);
//! ```
//!
//! ## Use Cases
//! - Post-quantum TLS key exchange (e.g., hybrid modes)
//! - Encrypted messaging systems requiring quantum resistance
//! - Secure session key establishment
//!
//! ## Security Notes
//! - Always keep your secret keys (`DecapsulationKey` or `CompressedDecapsulationKey`) confidential!
//! - This implementation aims to be constant-time, but always use the latest version and audit for updates.
//! - For more details, see the [NTRU Prime design page](https://ntruprime.cr.yp.to/).

#![no_std]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

pub use rand;
pub use rand_chacha;
pub use sha2;
pub use subtle;

mod error;
mod r3;
mod rq;
mod utils;
mod zx;

pub use error::Error;

use core::fmt::{self, Debug, Formatter};
use rand::{CryptoRng, SeedableRng};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size in bytes of a serialized public key.
pub const PUBLIC_KEY_SIZE: usize = 1158;

/// Size in bytes of a serialized secret (decapsulation) key.
pub const SECRET_KEY_SIZE: usize = 1763;

/// Size in bytes of a serialized ciphertext.
pub const CIPHERTEXT_SIZE: usize = 1039;

/// Size in bytes of a shared secret.
pub const SHARED_SECRET_SIZE: usize = 32;

const P: usize = 761;
const Q: usize = 4591;
const W: usize = 286;

const SMALL_ENCODE_SIZE: usize = 191;
const ROUNDED_ENCODE_SIZE: usize = 1007;
// SK layout: f(191) || ginv(191) || pk(1158) || rho(191) || Hash4(pk)(32) = 1763

// ---------------------------------------------------------------------------
// Wrapper types
// ---------------------------------------------------------------------------

/// Encapsulation (public) key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncapsulationKey(pub(crate) [u8; PUBLIC_KEY_SIZE]);

/// Decapsulation (secret) key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey(pub(crate) [u8; SECRET_KEY_SIZE]);

impl Debug for DecapsulationKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("***FILTERED***")
    }
}

/// Ciphertext produced by encapsulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(pub(crate) [u8; CIPHERTEXT_SIZE]);

/// Shared secret established by encapsulation/decapsulation. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub(crate) [u8; SHARED_SECRET_SIZE]);

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("***FILTERED***")
    }
}

macro_rules! impl_conversions {
    ($name:ident, $size:expr) => {
        impl From<[u8; $size]> for $name {
            fn from(arr: [u8; $size]) -> Self {
                Self(arr)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;
            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                if value.len() != $size {
                    return Err(Error::InvalidSize {
                        expected: $size,
                        actual: value.len(),
                    });
                }
                let mut arr = [0u8; $size];
                arr.copy_from_slice(value);
                Ok(Self(arr))
            }
        }

        #[cfg(any(feature = "alloc", feature = "std"))]
        impl TryFrom<Box<[u8]>> for $name {
            type Error = Error;
            fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_ref())
            }
        }

        #[cfg(any(feature = "alloc", feature = "std"))]
        impl TryFrom<Vec<u8>> for $name {
            type Error = Error;
            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        #[cfg(any(feature = "alloc", feature = "std"))]
        impl TryFrom<&Vec<u8>> for $name {
            type Error = Error;
            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }
    };
}

#[cfg(feature = "serde")]
macro_rules! impl_serde {
    ($name:ident, $size:expr) => {
        impl serdect::serde::Serialize for $name {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serdect::serde::Serializer,
            {
                serdect::array::serialize_hex_lower_or_bin(&self.0, s)
            }
        }

        impl<'de> serdect::serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serdect::serde::Deserializer<'de>,
            {
                let mut buf = [0u8; $size];
                let decoded = serdect::array::deserialize_hex_or_bin(&mut buf, d)?;
                if decoded.len() != $size {
                    return Err(serdect::serde::de::Error::invalid_length(
                        decoded.len(),
                        &concat!("exactly ", stringify!($size), " bytes"),
                    ));
                }
                Ok(Self(buf))
            }
        }
    };
}

impl_conversions!(EncapsulationKey, PUBLIC_KEY_SIZE);
impl_conversions!(DecapsulationKey, SECRET_KEY_SIZE);
impl_conversions!(Ciphertext, CIPHERTEXT_SIZE);
impl_conversions!(SharedSecret, SHARED_SECRET_SIZE);

#[cfg(feature = "serde")]
impl_serde!(EncapsulationKey, PUBLIC_KEY_SIZE);
#[cfg(feature = "serde")]
impl_serde!(DecapsulationKey, SECRET_KEY_SIZE);
#[cfg(feature = "serde")]
impl_serde!(Ciphertext, CIPHERTEXT_SIZE);
#[cfg(feature = "serde")]
impl_serde!(SharedSecret, SHARED_SECRET_SIZE);

impl ConstantTimeEq for DecapsulationKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for DecapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for DecapsulationKey {}

impl From<&DecapsulationKey> for EncapsulationKey {
    fn from(sk: &DecapsulationKey) -> Self {
        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        pk.copy_from_slice(&sk.0[2 * SMALL_ENCODE_SIZE..2 * SMALL_ENCODE_SIZE + PUBLIC_KEY_SIZE]);
        EncapsulationKey(pk)
    }
}

impl EncapsulationKey {
    /// Encapsulates this public key.
    /// Returns a ciphertext and shared secret.
    /// # Example
    /// ```
    /// use sntrup761::*;
    /// let (public_key, _private_key) = generate_key(rand::rng());
    /// let (cipher_text, shared_secret) = public_key.encapsulate(rand::rng());
    /// ```
    pub fn encapsulate(&self, mut rng: impl CryptoRng) -> (Ciphertext, SharedSecret) {
        let mut r = [0i8; P];
        zx::random::random_tsmall(&mut r, &mut rng);
        utils::create_cipher(r, &self.0)
    }

    /// Deterministic encapsulation from a 32-byte seed.
    ///
    /// The same seed and public key always produce the same ciphertext and shared secret.
    /// Uses ChaCha20Rng internally, so the output is stable across library versions.
    ///
    /// The seed must be generated from a cryptographically secure source.
    /// # Example
    /// ```
    /// use sntrup761::*;
    /// let (pk, _sk) = generate_key(rand::rng());
    /// let seed = [0x42u8; 32];
    /// let (ct1, ss1) = pk.encapsulate_deterministic(seed);
    /// let (ct2, ss2) = pk.encapsulate_deterministic(seed);
    /// assert_eq!(ct1, ct2);
    /// assert!(ss1 == ss2);
    /// ```
    pub fn encapsulate_deterministic(&self, seed: [u8; 32]) -> (Ciphertext, SharedSecret) {
        let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        self.encapsulate(rng)
    }
}

impl DecapsulationKey {
    /// Decapsulates ciphertext with this secret key.
    /// Always returns a shared secret (implicit rejection / IND-CCA2).
    /// On failure, returns a pseudorandom key derived from rho,
    /// indistinguishable from a valid key to an attacker.
    /// # Example
    /// ```
    /// use sntrup761::*;
    /// let (public_key, private_key) = generate_key(rand::rng());
    /// let (cipher_text, shared_secret_encap) = public_key.encapsulate(rand::rng());
    /// let shared_secret_decap = private_key.decapsulate(&cipher_text);
    /// assert!(shared_secret_encap == shared_secret_decap);
    /// ```
    pub fn decapsulate(&self, cstr: &Ciphertext) -> SharedSecret {
        SharedSecret(utils::decapsulate_inner(&cstr.0, &self.0))
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for SharedSecret {}

/// Compressed form of the decapsulation key (32-byte seed).
///
/// Since keypair generation from a seed is deterministic, the seed
/// is sufficient to reconstruct the full [`DecapsulationKey`] (and its
/// corresponding [`EncapsulationKey`]). This reduces storage from
/// 1763 bytes to 32 bytes.
///
/// **Security:** The seed is equivalent to the full secret key.
/// It must be kept secret and protected with the same care.
/// Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CompressedDecapsulationKey(pub(crate) [u8; 32]);

impl_conversions!(CompressedDecapsulationKey, 32);

#[cfg(feature = "serde")]
impl_serde!(CompressedDecapsulationKey, 32);

impl ConstantTimeEq for CompressedDecapsulationKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for CompressedDecapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for CompressedDecapsulationKey {}

impl Debug for CompressedDecapsulationKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("***FILTERED***")
    }
}

impl CompressedDecapsulationKey {
    /// Generates a random compressed decapsulation key.
    /// # Example
    /// ```
    /// use sntrup761::*;
    /// let csk = CompressedDecapsulationKey::generate(rand::rng());
    /// let (pk, sk) = csk.expand();
    /// ```
    pub fn generate(mut rng: impl CryptoRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }

    /// Expands this seed into the full keypair.
    pub fn expand(&self) -> (EncapsulationKey, DecapsulationKey) {
        generate_key_from_seed(self.0)
    }

    /// Convenience: expands the key and decapsulates in one step.
    ///
    /// This recomputes the full decapsulation key each time.
    /// If decapsulating multiple ciphertexts, use [`expand`](Self::expand)
    /// once and call [`DecapsulationKey::decapsulate`] on each.
    pub fn decapsulate(&self, cstr: &Ciphertext) -> SharedSecret {
        let (_ek, dk) = self.expand();
        dk.decapsulate(cstr)
    }
}

/// Generates a public and private keypair.
/// # Example
/// ```
/// use sntrup761::*;
/// let (public_key, private_key) = generate_key(rand::rng());
/// ```
pub fn generate_key(mut rng: impl CryptoRng) -> (EncapsulationKey, DecapsulationKey) {
    let mut g = [0i8; P];
    let mut gr = loop {
        zx::random::random_small(&mut g, &mut rng);
        let (mask, gr) = r3::reciprocal(g);
        if mask == 0 {
            break gr;
        }
    };
    let mut f = [0i8; P];
    zx::random::random_tsmall(&mut f, &mut rng);

    // Generate random rho for implicit rejection (raw random bytes, per PQClean)
    let mut rho = [0u8; SMALL_ENCODE_SIZE];
    rng.fill_bytes(&mut rho);

    let result = utils::derive_key(f, g, gr, rho);

    f.zeroize();
    g.zeroize();
    gr.zeroize();
    rho.zeroize();

    result
}

/// Generates a deterministic keypair from a 32-byte seed.
///
/// The same seed always produces the same keypair. Uses ChaCha20Rng
/// internally, so the output is stable across library versions.
///
/// The seed must be generated from a cryptographically secure source.
/// # Example
/// ```
/// use sntrup761::*;
/// let seed = [0x42u8; 32];
/// let (pk1, sk1) = generate_key_from_seed(seed);
/// let (pk2, sk2) = generate_key_from_seed(seed);
/// assert_eq!(pk1, pk2);
/// assert!(sk1 == sk2);
/// ```
pub fn generate_key_from_seed(seed: [u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
    let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    generate_key(rng)
}
