# sntrup761

A pure-Rust implementation of [Streamlined NTRU Prime](https://ntruprime.cr.yp.to/) 4591<sup>761</sup>.

NTRU Prime is a lattice-based cryptosystem aiming to improve the security of lattice schemes at minimal cost. It is thought to be resistant to quantum computing advances, in particular Shor's algorithm. It made it to NIST final round but was not selected for finalization.

Please read the [warnings](#warnings) before use.

The algorithm was authored by Daniel J. Bernstein, Chitchanok Chuengsatiansup, Tanja Lange & Christine van Vredendaal. This implementation is aligned with the [PQClean reference](https://github.com/PQClean/PQClean/tree/master/crypto_kem/sntrup761) and verified against the [IETF draft](https://datatracker.ietf.org/doc/draft-josefsson-ntruprime-streamlined/) KAT vectors.

#### Parameter set

| Parameter | Value |
|-----------|------:|
| p         |   761 |
| q         |  4591 |
| w         |   286 |

#### Sizes

Note that Streamlined NTRU Prime 761 sizes are fixed. All keys and ciphertexts use
a canonical encoding which is enfored by the code i.e. it should not be feasible to
modify the encoding of an existing public key or a ciphertext without changing is
mathematical value.

| Type                        | Bytes |
|-----------------------------|------:|
| Public Key                  |  1158 |
| Private Key                 |  1763 |
| Compressed Private Key      |    32 |
| Ciphertext                  |  1039 |
| Shared Key                  |    32 |

## Features

- Pure Rust, `no_std`-compatible, dependency-minimal
- IND-CCA2 secure with implicit rejection
- Constant-time operations throughout (branchless sort, constant-time comparison and selection)
- Optional `serde` support via the `serde` feature
- Deterministic key generation and encapsulation from a 32-byte seed
- Compressed decapsulation key (32-byte seed instead of 1763 bytes)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
sntrup761 = "0.2"
```

### Feature Flags

All features are opt-in. Enable them in your `Cargo.toml`:

```toml
[dependencies]
sntrup761 = { version = "0.2", features = ["std", "serde"] }
```

| Feature | Default | Description |
|---------|:-------:|-------------|
| `alloc` | no | Enables `TryFrom<Vec<u8>>` and `TryFrom<Box<[u8]>>` conversions (requires an allocator) |
| `std`   | no | Enables standard library support (implies `alloc` functionality) |
| `serde` | no | Enables `Serialize`/`Deserialize` for all key and ciphertext types (via `serdect` for constant-time hex encoding) |
| `js`    | no | Enables WebAssembly support for `wasm32-unknown-unknown` by configuring `getrandom` to use JavaScript's `crypto.getRandomValues()` |

## Usage

### Basic key exchange

```rust
use sntrup761::*;

// Key generation
let (public_key, private_key) = generate_key(rand::rng());

// Encapsulation (sender side)
let (cipher_text, shared_secret_sender) = public_key.encapsulate(rand::rng());

// Decapsulation (receiver side — implicit rejection: always returns a key)
let shared_secret_receiver = private_key.decapsulate(&cipher_text);

assert!(shared_secret_sender == shared_secret_receiver);
```

### Deterministic key generation

Useful for deriving the same keypair from stored entropy:

```rust
use sntrup761::*;

let seed = [0x42u8; 32]; // must come from a cryptographically secure source
let (pk1, sk1) = generate_key_from_seed(seed);
let (pk2, sk2) = generate_key_from_seed(seed);
assert_eq!(pk1, pk2);
assert!(sk1 == sk2);
```

### Deterministic encapsulation

Produces the same ciphertext and shared secret from a given seed and public key:

```rust
use sntrup761::*;

let (pk, _sk) = generate_key(rand::rng());
let seed = [0x42u8; 32]; // must come from a cryptographically secure source
let (ct1, ss1) = pk.encapsulate_deterministic(seed);
let (ct2, ss2) = pk.encapsulate_deterministic(seed);
assert_eq!(ct1, ct2);
assert!(ss1 == ss2);
```

### Compressed decapsulation key

Store only 32 bytes instead of the full 1763-byte secret key:

```rust
use sntrup761::*;

let compressed = CompressedDecapsulationKey::generate(rand::rng());
let (pk, sk) = compressed.expand();

// Or decapsulate directly (re-expands the full key each time)
let (ct, ss) = pk.encapsulate(rand::rng());
let ss2 = compressed.decapsulate(&ct);
assert!(ss == ss2);
```

### Serialization with serde

Enable the `serde` feature:

```toml
sntrup761 = { version = "0.2", features = ["serde"] }
```

Keys and ciphertexts serialize to hex in human-readable formats (JSON) and raw bytes in binary formats (postcard, bincode):

```rust,ignore
use sntrup761::*;

let (pk, sk) = generate_key(rand::rng());
let json = serde_json::to_string(&pk).unwrap();
let pk2: EncapsulationKey = serde_json::from_str(&json).unwrap();
assert_eq!(pk, pk2);
```

## WebAssembly

To compile for `wasm32-unknown-unknown`, enable the `js` feature so that `getrandom` uses JavaScript's `crypto.getRandomValues()` for randomness:

```toml
[dependencies]
sntrup761 = { version = "0.2", features = ["js"] }
```

Install the target and build:

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --features js
```

For `wasm32-wasi` (or `wasm32-wasip1`), the `js` feature is **not** needed since WASI provides its own random source.

### wasm-bindgen example

```rust,ignore
use sntrup761::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn keygen() -> Vec<u8> {
    let (pk, _sk) = generate_key(rand::rng());
    pk.as_ref().to_vec()
}

#[wasm_bindgen]
pub fn encapsulate(pk_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk = EncapsulationKey::try_from(pk_bytes)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let (ct, ss) = pk.encapsulate(rand::rng());

    // Return ciphertext || shared_secret
    let mut out = ct.as_ref().to_vec();
    out.extend_from_slice(ss.as_ref());
    Ok(out)
}

#[wasm_bindgen]
pub fn decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk = DecapsulationKey::try_from(sk_bytes)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let ct = Ciphertext::try_from(ct_bytes)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let ss = sk.decapsulate(&ct);
    Ok(ss.as_ref().to_vec())
}
```

## Benchmarks

Measured on Apple M1 (aarch64). The NEON column uses ARM NEON SIMD intrinsics that are baseline on `aarch64`; the scalar column uses the `force-scalar` feature to disable them. SHA-2 hashing uses hardware intrinsics via `sha2-asm` on both aarch64 and x86_64.

| Operation    | Scalar (pure Rust) | NEON (aarch64) | Speedup |
|--------------|-------------------:|---------------:|--------:|
| Key Gen      |          2,850 µs  |      1,384 µs  |   2.1×  |
| Encapsulate  |            301 µs  |         98 µs  |   3.1×  |
| Decapsulate  |            762 µs  |        183 µs  |   4.2×  |

Measured on AMD Ryzen 9 5900HX (x86_64). The AVX2 column uses 256-bit SIMD intrinsics enabled by `target-cpu=native`; the scalar column uses the `force-scalar` feature to disable them.

| Operation    | Scalar (pure Rust) | AVX2 (x86_64) | Speedup |
|--------------|-------------------:|---------------:|--------:|
| Key Gen      |          2,514 µs  |        756 µs  |   3.3×  |
| Encapsulate  |            390 µs  |         56 µs  |   6.9×  |
| Decapsulate  |          1,089 µs  |         93 µs  |  11.8×  |

AVX2 optimizations are enabled automatically on `x86_64` when AVX2 is available. NEON optimizations are enabled automatically on `aarch64` targets. To force pure-Rust (scalar) code, enable the `force-scalar` feature.

## Security Properties

- **IND-CCA2 security** via implicit rejection: decapsulation always returns a shared key. On failure, a pseudorandom key is derived from secret randomness (`rho`), making it indistinguishable from a valid key to an attacker.
- **Hash domain separation**: all hashes use prefix bytes (following the NTRU Prime specification).
- **Constant-time operations**: branchless sorting (djbsort), constant-time weight checks, constant-time ciphertext comparison, and constant-time selection in decapsulation.
- **Zeroization**: secret key material is zeroized on drop.

## Warnings

#### Implementation

This implementation has not undergone any security auditing and while care has been taken no guarantees can be made for either correctness or the constant time running of the underlying functions. **Please use at your own risk.**

#### Algorithm

Streamlined NTRU Prime was first published in 2016. The algorithm still requires careful security review. Please see [here](https://ntruprime.cr.yp.to/warnings.html) for further warnings from the authors regarding NTRU Prime and lattice-based encryption schemes.

# License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
