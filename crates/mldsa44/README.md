# mldsa44

**ML-DSA-44** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) digital signature library. 

Built in Rust on [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), compiled to WASM.

ML-DSA-44 (formerly **CRYSTALS-Dilithium**) provides NIST Level 2 post-quantum signature security.

## Native Rust usage

```rust
use mldsa44::*;

let kp = generate_keypair();
let sig = sign(&kp.seed, b"hello");
assert!(verify(&kp.verifying_key, b"hello", &sig));
```

## Install

```bash
npm install mldsa44-wasm
```

## Usage

```ts
import {generateKeypair, sign, verify} from 'mldsa44-wasm';

// Generate keypair (32-byte seed + 1312-byte verifying key)
const {seed, verifyingKey} = generateKeypair();

// Sign a message (deterministic)
const signature = sign(seed, new TextEncoder().encode('hello'));

// Verify
const valid = verify(verifyingKey, new TextEncoder().encode('hello'), signature);
```

## Sizes

| Value                      | Size        |
|----------------------------|-------------|
| Seed (private key)         | 32 bytes    |
| Verifying key (public key) | 1,312 bytes |
| Signature                  | 2,420 bytes |

## Security

- Deterministic signing (no randomness at sign time)
- Seed zeroized on drop
- Based on [`ml-dsa`](https://crates.io/crates/ml-dsa) by RustCrypto

## License

Dual-licensed under the [MIT License](../../LICENSE-MIT) or [Apache-2.0 License](../../LICENSE-APACHE).