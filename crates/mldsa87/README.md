# mldsa87-wasm

**ML-DSA-87** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) digital signature library. 

Built in Rust on [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), compiled to WASM.

ML-DSA-87 (formerly **CRYSTALS-Dilithium**) provides NIST Level 5 post-quantum signature security.

## Native Rust usage

```rust
use mldsa87_wasm_rs::*;

let kp = generate_keypair();
let sig = sign(&kp.seed, b"hello");
assert!(verify(&kp.verifying_key, b"hello", &sig));
```

## Install

```bash
npm install mldsa87-wasm
```

## Usage

```ts
import {generateKeypair, sign, verify} from 'mldsa87-wasm';

// Generate keypair (32-byte seed + 2592-byte verifying key)
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
| Verifying key (public key) | 2,592 bytes |
| Signature                  | 4,627 bytes |

## Security

- Deterministic signing (no randomness at sign time)
- Seed zeroized on drop
- Based on [`ml-dsa`](https://crates.io/crates/ml-dsa) by RustCrypto

## License

Dual-licensed under the [MIT License](../../LICENSE-MIT) or [Apache-2.0 License](../../LICENSE-APACHE).