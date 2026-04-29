# mldsa87

**ML-DSA-87** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) digital signature library. 

Built in Rust on [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), compiled to WASM.

ML-DSA-87 (formerly **CRYSTALS-Dilithium**) provides NIST Level 5 post-quantum signature security.

## Native Rust usage

```rust
use mldsa87::*;

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
import {Signer, generateKeypair, sign, verify} from 'mldsa87-wasm';

//=========== Safe (seed lives inside WASM memory) ===========

// Automatic cleanup (modern browsers)
const signer = new Signer(seed); // Signer generates the keypair with seed argument

// Sign a message
const sig = signer.sign(message);
// seed zeroized when signer is GC'd

// Verify
const valid = verify(signer.verifyingKey, new TextEncoder().encode('hello'), sig);
console.log(valid); // true

//=========== !WARNING! - UNSAFE ===========

// Generate keypair (32-byte seed + 2592-byte verifying key)
const {seed, verifyingKey} = generateKeypair();

// Sign a message (deterministic)
const signature = sign(seed, new TextEncoder().encode('hello'));

// Verify
const valid = verify(verifyingKey, new TextEncoder().encode('hello'), signature);
```

> **Memory management:** In all modern browsers (and wasm-bindgen ≥ 0.2.91), WASM memory is freed automatically via the TC39 weak references proposal when the JS object goes out of scope.
>
> In practice, you often don't need to think about this. For deterministic cleanup or environments without weak reference support (older browsers, some Node.js setups), use `using` (TypeScript 5.2+ / ES2026) or call `.free()` manually.
>
> Never call `.free()` on a `using`-managed instance otherwise it will double-free.

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