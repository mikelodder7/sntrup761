//! Tests that feature flags correctly gate the public API.
//!
//! Run individual features:
//!   cargo test --no-default-features --features kgen --test features
//!   cargo test --no-default-features --features ecap --test features
//!   cargo test --no-default-features --features dcap --test features
#![allow(missing_docs)]

use sntrup761::*;

// ---------------------------------------------------------------------------
// kgen — key generation
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
mod kgen {
    use super::*;

    #[test]
    fn generate_key_available() {
        let (pk, sk) = generate_key(rand::rng());
        assert_eq!(pk.as_ref().len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_ref().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn generate_key_from_seed_available() {
        let seed = [0x42u8; 32];
        let (pk1, sk1) = generate_key_from_seed(seed);
        let (pk2, sk2) = generate_key_from_seed(seed);
        assert_eq!(pk1, pk2);
        assert!(sk1 == sk2);
    }

    #[test]
    fn compressed_key_generate_and_expand() {
        let csk = CompressedDecapsulationKey::generate(rand::rng());
        let (pk, sk) = csk.expand();
        assert_eq!(pk.as_ref().len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_ref().len(), SECRET_KEY_SIZE);

        // expand is deterministic
        let (pk2, sk2) = csk.expand();
        assert_eq!(pk, pk2);
        assert!(sk == sk2);
    }

    #[test]
    fn encapsulation_key_from_decapsulation_key() {
        let (pk, sk) = generate_key(rand::rng());
        let pk_from_sk = EncapsulationKey::from(&sk);
        assert_eq!(pk, pk_from_sk);
    }
}

// ---------------------------------------------------------------------------
// ecap — encapsulation (works without kgen by constructing key from bytes)
// ---------------------------------------------------------------------------

#[cfg(feature = "ecap")]
mod ecap {
    use super::*;

    #[test]
    fn encapsulate_available() {
        let pk = EncapsulationKey::from([0u8; PUBLIC_KEY_SIZE]);
        let (ct, ss) = pk.encapsulate(rand::rng());
        assert_eq!(ct.as_ref().len(), CIPHERTEXT_SIZE);
        assert_eq!(ss.as_ref().len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn encapsulate_deterministic_available() {
        let pk = EncapsulationKey::from([0u8; PUBLIC_KEY_SIZE]);
        let seed = [0x42u8; 32];
        let (ct1, ss1) = pk.encapsulate_deterministic(seed);
        let (ct2, ss2) = pk.encapsulate_deterministic(seed);
        assert_eq!(ct1, ct2);
        assert!(ss1 == ss2);
    }
}

// ---------------------------------------------------------------------------
// dcap — decapsulation (works without kgen/ecap by constructing from bytes)
// ---------------------------------------------------------------------------

#[cfg(feature = "dcap")]
mod dcap {
    use super::*;

    #[test]
    fn decapsulate_available() {
        let sk = DecapsulationKey::from([0u8; SECRET_KEY_SIZE]);
        let ct = Ciphertext::from([0u8; CIPHERTEXT_SIZE]);
        let ss = sk.decapsulate(&ct);
        assert_eq!(ss.as_ref().len(), SHARED_SECRET_SIZE);
    }
}

// ---------------------------------------------------------------------------
// Combined feature tests
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap"))]
mod kgen_ecap {
    use super::*;

    #[test]
    fn generate_then_encapsulate() {
        let (pk, _sk) = generate_key(rand::rng());
        let (ct, ss) = pk.encapsulate(rand::rng());
        assert_eq!(ct.as_ref().len(), CIPHERTEXT_SIZE);
        assert_eq!(ss.as_ref().len(), SHARED_SECRET_SIZE);
    }
}

#[cfg(all(feature = "kgen", feature = "dcap"))]
mod kgen_dcap {
    use super::*;

    #[test]
    fn compressed_key_decapsulate() {
        let csk = CompressedDecapsulationKey::generate(rand::rng());
        let (pk, _sk) = csk.expand();
        // Need ecap to produce a valid ciphertext, so use raw bytes
        let ct = Ciphertext::from([0u8; CIPHERTEXT_SIZE]);
        let ss = csk.decapsulate(&ct);
        assert_eq!(ss.as_ref().len(), SHARED_SECRET_SIZE);
        let _ = pk;
    }
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod full {
    use super::*;

    #[test]
    fn full_roundtrip() {
        let (pk, sk) = generate_key(rand::rng());
        let (ct, ss_enc) = pk.encapsulate(rand::rng());
        let ss_dec = sk.decapsulate(&ct);
        assert!(ss_enc == ss_dec);
    }

    #[test]
    fn compressed_full_roundtrip() {
        let csk = CompressedDecapsulationKey::generate(rand::rng());
        let (pk, _sk) = csk.expand();
        let (ct, ss_enc) = pk.encapsulate(rand::rng());
        let ss_dec = csk.decapsulate(&ct);
        assert!(ss_enc == ss_dec);
    }
}
