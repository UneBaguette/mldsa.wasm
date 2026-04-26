# mldsa65-wasm-rs

**ML-DSA-65** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) digital signature library. Built in Rust on [
`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), compiled to WASM.

ML-DSA-65 (formerly **CRYSTALS-Dilithium**) provides NIST Level 3 post-quantum signature security.

## Install

```bash
npm install mldsa65-wasm-rs
```

## Usage

```ts
import {generateKeypair, sign, verify} from 'mldsa65-wasm-rs';

// Generate keypair (32-byte seed + 1952-byte verifying key)
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
| Verifying key (public key) | 1,952 bytes |
| Signature                  | 3,309 bytes |

## Native Rust usage

```rust
use mldsa65_wasm_rs::*;

let kp = generate_keypair();
let sig = sign( & kp.seed, b"hello");
assert!(verify(&kp.verifying_key, b"hello", &sig));
```

## Security

- Deterministic signing (no randomness at sign time)
- Seed zeroized on drop
- Based on [`ml-dsa`](https://crates.io/crates/ml-dsa) by RustCrypto

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
