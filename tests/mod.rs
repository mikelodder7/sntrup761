#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    extern crate sntrup761 as sntrup;

    use self::sntrup::*;

    #[test]
    fn keygen_encap_decap_roundtrip() {
        for _ in 0..5 {
            let (pk, sk) = generate_key(rand::rng());
            let (ct, ss_encap) = pk.encapsulate(rand::rng());
            let ss_decap = sk.decapsulate(&ct);
            assert!(ss_encap == ss_decap, "shared secrets must match");
        }
    }

    #[test]
    fn implicit_rejection() {
        // Decapsulation with corrupted ciphertext should still return a key
        // (not panic or return an error), but a DIFFERENT key.
        let (pk, sk) = generate_key(rand::rng());
        let (ct, ss_encap) = pk.encapsulate(rand::rng());
        // Corrupt the ciphertext
        let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
        ct_bytes.copy_from_slice(ct.as_ref());
        ct_bytes[0] ^= 0xFF;
        ct_bytes[100] ^= 0x42;
        let ct_bad = Ciphertext::from(ct_bytes);
        let ss_decap = sk.decapsulate(&ct_bad);
        // Should return a valid key, but different from the encapsulated one
        assert!(
            ss_encap != ss_decap,
            "corrupted CT must produce different key"
        );
        // Key should be deterministic for the same corrupted CT + SK
        let ss_decap2 = sk.decapsulate(&ct_bad);
        assert!(
            ss_decap == ss_decap2,
            "repeated decap must be deterministic"
        );
    }

    #[test]
    fn wrong_secret_key_gives_different_key() {
        let (pk1, _sk1) = generate_key(rand::rng());
        let (_pk2, sk2) = generate_key(rand::rng());
        let (ct, ss_encap) = pk1.encapsulate(rand::rng());
        let ss_decap = sk2.decapsulate(&ct);
        assert!(ss_encap != ss_decap, "wrong SK must produce different key");
    }

    #[test]
    fn constant_time_decap_always_returns_key() {
        // Verify that decapsulate always returns SHARED_SECRET_SIZE bytes
        let (pk, sk) = generate_key(rand::rng());
        let (ct, _ss) = pk.encapsulate(rand::rng());
        let result = sk.decapsulate(&ct);
        assert_eq!(result.as_ref().len(), SHARED_SECRET_SIZE);

        // Even with garbage ciphertext
        let garbage_ct = Ciphertext::from([0xAB_u8; CIPHERTEXT_SIZE]);
        let result2 = sk.decapsulate(&garbage_ct);
        assert_eq!(result2.as_ref().len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn generate_key_from_seed_is_deterministic() {
        let seed = [0xABu8; 32];
        let (pk1, sk1) = generate_key_from_seed(seed);
        let (pk2, sk2) = generate_key_from_seed(seed);
        assert_eq!(pk1, pk2);
        assert!(sk1 == sk2, "same seed must produce same SK");

        // Different seed produces different key
        let (pk3, _sk3) = generate_key_from_seed([0xCDu8; 32]);
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn kat0_decapsulation() {
        // IETF draft-josefsson-ntruprime-streamlined-00, test vector 0
        let sk_hex = include_str!("data/kat0_sk.hex");
        let ct_hex = include_str!("data/kat0_ct.hex");
        let ss_hex = include_str!("data/kat0_ss.hex");

        let sk = DecapsulationKey::try_from(
            hex::decode(sk_hex.trim())
                .expect("invalid SK hex")
                .as_slice(),
        )
        .expect("SK size mismatch");
        let ct = Ciphertext::try_from(
            hex::decode(ct_hex.trim())
                .expect("invalid CT hex")
                .as_slice(),
        )
        .expect("CT size mismatch");
        let ss_expected = hex::decode(ss_hex.trim()).expect("invalid SS hex");

        let ss = sk.decapsulate(&ct);
        assert_eq!(ss.as_ref(), &ss_expected[..], "KAT0 shared secret mismatch");
    }

    #[test]
    fn kat1_decapsulation() {
        // IETF draft-josefsson-ntruprime-streamlined-00, test vector 1
        let sk_hex = include_str!("data/kat1_sk.hex");
        let ct_hex = include_str!("data/kat1_ct.hex");
        let ss_hex = include_str!("data/kat1_ss.hex");

        let sk = DecapsulationKey::try_from(
            hex::decode(sk_hex.trim())
                .expect("invalid SK hex")
                .as_slice(),
        )
        .expect("SK size mismatch");
        let ct = Ciphertext::try_from(
            hex::decode(ct_hex.trim())
                .expect("invalid CT hex")
                .as_slice(),
        )
        .expect("CT size mismatch");
        let ss_expected = hex::decode(ss_hex.trim()).expect("invalid SS hex");

        let ss = sk.decapsulate(&ct);
        assert_eq!(ss.as_ref(), &ss_expected[..], "KAT1 shared secret mismatch");
    }

    #[test]
    fn encapsulation_key_from_decapsulation_key() {
        let (pk, sk) = generate_key(rand::rng());
        let pk_from_sk = EncapsulationKey::from(&sk);
        assert_eq!(pk, pk_from_sk);

        // Encapsulating with the extracted key should produce a valid shared secret
        let (ct, ss_encap) = pk_from_sk.encapsulate(rand::rng());
        let ss_decap = sk.decapsulate(&ct);
        assert!(ss_encap == ss_decap, "shared secrets must match");
    }

    #[test]
    fn compressed_decapsulation_key_roundtrip() {
        let csk = CompressedDecapsulationKey::generate(rand::rng());
        let (pk, sk) = csk.expand();

        // Encapsulate with the expanded public key
        let (ct, ss_encap) = pk.encapsulate(rand::rng());

        // Decapsulate with the expanded secret key
        let ss_decap = sk.decapsulate(&ct);
        assert!(
            ss_encap == ss_decap,
            "shared secrets must match after expand"
        );

        // Convenience decapsulate directly from compressed key
        let ss_decap2 = csk.decapsulate(&ct);
        assert!(ss_encap == ss_decap2, "convenience decapsulate must match");

        // Second expand produces the same keypair
        let (pk2, sk2) = csk.expand();
        assert_eq!(pk, pk2);
        assert!(sk == sk2, "expand must be deterministic");
    }

    #[test]
    fn compressed_decapsulation_key_from_bytes() {
        let csk = CompressedDecapsulationKey::generate(rand::rng());
        let bytes = csk.as_ref().to_vec();
        let csk2 = CompressedDecapsulationKey::try_from(bytes.as_slice()).unwrap();
        assert!(csk == csk2, "roundtrip through bytes must preserve key");

        let (pk1, _) = csk.expand();
        let (pk2, _) = csk2.expand();
        assert_eq!(pk1, pk2);
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::sntrup::*;

        #[test]
        fn json_roundtrip_encapsulation_key() {
            let (pk, _sk) = generate_key(rand::rng());
            let json = serde_json::to_string(&pk).expect("serialize pk");
            // Human-readable format should be a hex string
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(parsed.is_string(), "pk should serialize as hex string");
            assert_eq!(parsed.as_str().unwrap().len(), PUBLIC_KEY_SIZE * 2);
            let pk2: EncapsulationKey = serde_json::from_str(&json).expect("deserialize pk");
            assert_eq!(pk, pk2);
        }

        #[test]
        fn json_roundtrip_decapsulation_key() {
            let (_pk, sk) = generate_key(rand::rng());
            let json = serde_json::to_string(&sk).expect("serialize sk");
            let sk2: DecapsulationKey = serde_json::from_str(&json).expect("deserialize sk");
            assert!(sk == sk2, "decapsulation keys must match");
        }

        #[test]
        fn json_roundtrip_ciphertext() {
            let (pk, _sk) = generate_key(rand::rng());
            let (ct, _ss) = pk.encapsulate(rand::rng());
            let json = serde_json::to_string(&ct).expect("serialize ct");
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(parsed.is_string(), "ct should serialize as hex string");
            assert_eq!(parsed.as_str().unwrap().len(), CIPHERTEXT_SIZE * 2);
            let ct2: Ciphertext = serde_json::from_str(&json).expect("deserialize ct");
            assert_eq!(ct, ct2);
        }

        #[test]
        fn json_roundtrip_shared_secret() {
            let (pk, _sk) = generate_key(rand::rng());
            let (_ct, ss) = pk.encapsulate(rand::rng());
            let json = serde_json::to_string(&ss).expect("serialize ss");
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(parsed.is_string(), "ss should serialize as hex string");
            assert_eq!(parsed.as_str().unwrap().len(), SHARED_SECRET_SIZE * 2);
            let ss2: SharedSecret = serde_json::from_str(&json).expect("deserialize ss");
            assert!(ss == ss2, "shared secrets must match");
        }

        #[test]
        fn postcard_roundtrip_encapsulation_key() {
            let (pk, _sk) = generate_key(rand::rng());
            let bytes = postcard::to_stdvec(&pk).expect("serialize pk");
            let pk2: EncapsulationKey = postcard::from_bytes(&bytes).expect("deserialize pk");
            assert_eq!(pk, pk2);
        }

        #[test]
        fn postcard_roundtrip_decapsulation_key() {
            let (_pk, sk) = generate_key(rand::rng());
            let bytes = postcard::to_stdvec(&sk).expect("serialize sk");
            let sk2: DecapsulationKey = postcard::from_bytes(&bytes).expect("deserialize sk");
            assert!(sk == sk2, "decapsulation keys must match");
        }

        #[test]
        fn postcard_roundtrip_ciphertext() {
            let (pk, _sk) = generate_key(rand::rng());
            let (ct, _ss) = pk.encapsulate(rand::rng());
            let bytes = postcard::to_stdvec(&ct).expect("serialize ct");
            let ct2: Ciphertext = postcard::from_bytes(&bytes).expect("deserialize ct");
            assert_eq!(ct, ct2);
        }

        #[test]
        fn postcard_roundtrip_shared_secret() {
            let (pk, _sk) = generate_key(rand::rng());
            let (_ct, ss) = pk.encapsulate(rand::rng());
            let bytes = postcard::to_stdvec(&ss).expect("serialize ss");
            let ss2: SharedSecret = postcard::from_bytes(&bytes).expect("deserialize ss");
            assert!(ss == ss2, "shared secrets must match");
        }

        #[test]
        fn json_invalid_size_returns_error() {
            // Too short hex string for EncapsulationKey
            let bad_json = "\"aabbccdd\"";
            let result = serde_json::from_str::<EncapsulationKey>(bad_json);
            assert!(result.is_err());
        }

        #[test]
        fn json_full_kem_roundtrip() {
            // Serialize all components, deserialize, and verify KEM still works
            let (pk, sk) = generate_key(rand::rng());
            let (ct, ss_encap) = pk.encapsulate(rand::rng());

            let pk_json = serde_json::to_string(&pk).unwrap();
            let sk_json = serde_json::to_string(&sk).unwrap();
            let ct_json = serde_json::to_string(&ct).unwrap();

            let sk2: DecapsulationKey = serde_json::from_str(&sk_json).unwrap();
            let ct2: Ciphertext = serde_json::from_str(&ct_json).unwrap();
            let _pk2: EncapsulationKey = serde_json::from_str(&pk_json).unwrap();

            let ss_decap = sk2.decapsulate(&ct2);
            assert!(ss_encap == ss_decap, "KEM roundtrip through JSON must work");
        }
    }
}
