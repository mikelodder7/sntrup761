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

| Type        | Bytes |
|-------------|------:|
| Public Key  |  1158 |
| Private Key |  1763 |
| Ciphertext  |  1039 |
| Shared Key  |    32 |

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
sntrup761 = "0.1.0"
```

Optional features:

```toml
[dependencies]
sntrup761 = { version = "0.1.0", features = ["serde"] }
```

| Feature | Description |
|---------|-------------|
| `alloc` | Enables `TryFrom<Vec<u8>>` and `TryFrom<Box<[u8]>>` conversions |
| `std`   | Implies `alloc`, enables standard library |
| `serde` | Enables Serialize/Deserialize for all key and ciphertext types |

## Usage

```rust
use sntrup761::*;

// Key generation
let (public_key, private_key) = generate_key(rand::rng());

// Encapsulation
let (cipher_text, shared_secret_sender) = public_key.encapsulate(rand::rng());

// Decapsulation (implicit rejection: always returns a key)
let shared_secret_receiver = private_key.decapsulate(&cipher_text);

assert!(shared_secret_sender == shared_secret_receiver);
```

#### Deterministic key generation

```rust
use sntrup761::*;

let seed = [0x42u8; 32];
let (pk1, sk1) = generate_key_from_seed(seed);
let (pk2, sk2) = generate_key_from_seed(seed);
assert_eq!(pk1, pk2);
```

#### Compressed decapsulation key

```rust
use sntrup761::*;

// Store only 32 bytes instead of 1763
let compressed = CompressedDecapsulationKey::generate(rand::rng());
let (pk, sk) = compressed.expand();

// Or decapsulate directly (re-expands each time)
let (ct, ss) = pk.encapsulate(rand::rng());
let ss2 = compressed.decapsulate(&ct);
assert!(ss == ss2);
```

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