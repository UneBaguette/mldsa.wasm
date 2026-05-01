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
import { Signer, verify } from 'mldsa87-wasm';

//=========== Safe (seed lives inside WASM memory) ===========

// seed is a base64-encoded 32-byte value that deterministically derives the ML-DSA keypair.
// You are responsible for providing it. Store it securely and never expose it!
// The seed stays inside WASM memory and is zeroized when the Signer is freed or garbage collected.
const signer = new Signer(seed);

// Sign a message
const sig = signer.sign(new TextEncoder().encode('hello'));
// seed zeroized when signer is GC'd

// With optional context (per ML-DSA spec)
const sigWithCtx = signer.sign(new TextEncoder().encode('hello'), new TextEncoder().encode('ctx'));

const vk = signer.verifyingKey();

// Verify
const valid = verify(vk, new TextEncoder().encode('hello'), sig);
console.log(valid); // true

//=========== !WARNING! - UNSAFE ===========

// generateKeypair generates a fresh random seed via the system RNG.
// The seed is returned to JS memory.
// You are responsible for zeroizing it after use.
import { generateKeypair, sign } from 'mldsa65-wasm';

// Generate a keypair
const { seed, verifyingKey } = generateKeypair();

// Sign a message (deterministic but unsafe)
const signature = sign(seed, new TextEncoder().encode('hello'));

// Verify
const valid = verify(verifyingKey, new TextEncoder().encode('hello'), signature);
console.log(valid); // true
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