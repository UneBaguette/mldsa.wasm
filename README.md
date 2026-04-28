# mldsa.wasm

> Post-quantum digital signatures for the web. ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) compiled to WebAssembly, with TypeScript bindings and a native Rust API.

ML-DSA (formerly **CRYSTALS-Dilithium**) is NIST's standardized post-quantum signature scheme. 

This repository provides all three parameter sets as standalone npm packages.

And a **unified** Rust crate, built on [`ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) by **RustCrypto**.

## Packages

### Rust (crates.io)

| Crate                             | Description                |
|-----------------------------------|----------------------------|
| [`mldsa44`](crates/mldsa44)       | ML-DSA-44 (NIST Level 2)   |
| [`mldsa65`](crates/mldsa65)       | ML-DSA-65 (NIST Level 3)   |
| [`mldsa87`](crates/mldsa87)       | ML-DSA-87 (NIST Level 5)   |
| [`mldsa-core`](crates/mldsa-core) | Shared core implementation |

### npm

| Package                          | Security Level | npm                         |
|----------------------------------|----------------|-----------------------------|
| [`mldsa44-wasm`](crates/mldsa44) | NIST Level 2   | `npm install mldsa44-wasm`  |
| [`mldsa65-wasm`](crates/mldsa65) | NIST Level 3   | `npm install mldsa65-wasm`  |
| [`mldsa87-wasm`](crates/mldsa87) | NIST Level 5   | `npm install mldsa87-wasm`  |
| `mldsa-wasm-rs`                  | All variants   | `npm install mldsa-wasm-rs` |

## Parameter sets

| Variant   | Security Level | Seed | Verifying Key | Signature   |
|-----------|----------------|------|---------------|-------------|
| ML-DSA-44 | NIST Level 2   | 32 B | 1,312 bytes   | 2,420 bytes |
| ML-DSA-65 | NIST Level 3   | 32 B | 1,952 bytes   | 3,309 bytes |
| ML-DSA-87 | NIST Level 5   | 32 B | 2,592 bytes   | 4,627 bytes |

## JavaScript / TypeScript

### Standalone packages

```bash
npm install mldsa65-wasm
```

```ts
import { generateKeypair, sign, verify } from 'mldsa65-wasm';

// Generate a keypair
const { seed, verifyingKey } = generateKeypair();

// Sign a message (deterministic)
const signature = sign(seed, new TextEncoder().encode('hello'));

// Verify
const valid = verify(verifyingKey, new TextEncoder().encode('hello'), signature);
console.log(valid); // true
```

### Unified package with subpath exports

```bash
npm install mldsa-wasm-rs
```

```ts
import { generateKeypair, sign, verify } from 'mldsa-wasm-rs/65';
// or
import { generateKeypair, sign, verify } from 'mldsa-wasm-rs/44';
import { generateKeypair, sign, verify } from 'mldsa-wasm-rs/87';
```

## Rust

Each variant is a standalone crate:

```toml
[dependencies]
mldsa65 = "0.1.0"
```

```rust
use mldsa65::*;
 
let kp = generate_keypair();
let sig = sign(&kp.seed, b"hello");
assert!(verify(&kp.verifying_key, b"hello", &sig));
```

Multiple variants:

```toml
[dependencies]
mldsa44 = "0.1"
mldsa65 = "0.1"
mldsa87 = "0.1"
```

```rust
let kp44 = mldsa44::generate_keypair();
let kp65 = mldsa65::generate_keypair();
let kp87 = mldsa87::generate_keypair();
```

## Building

### Prerequisites

- [Rust](https://rustup.rs/) with the `wasm32-unknown-unknown` target
- [`wasm-bindgen-cli`](https://rustwasm.github.io/wasm-bindgen/)
- [`wasm-opt`](https://github.com/WebAssembly/binaryen) (Binaryen)
- [Node.js](https://nodejs.org/)

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

### Native tests

```bash
cargo test --workspace
```

### WASM tests

```bash
# Single variant
make test-wasm65
 
# All variants
make test-wasm
```

### Build npm packages

```bash
# Single variant
make wasm65
 
# All variants + unified package
make wasm
 
# Run all tests (native + wasm)
make test-all
```

### Build npm packages

```bash
# Build a single variant
make wasm

# Build all variants + unified package
make wasm-all

# Run all tests (native + wasm)
make test-all
```

## Security

- **Deterministic signing** | No randomness required at sign time, eliminating a class of implementation bugs
- **Zeroized secrets** | Seed is zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)
- **No unsafe code**
- **FIPS 204 compliant** | Built on [`ml-dsa`](https://crates.io/crates/ml-dsa) by **RustCrypto**

This library has **not** been independently **audited**. Use in production **at your own risk**.

## License

Dual-licensed under the [MIT License](LICENSE-MIT) or [Apache-2.0 License](LICENSE-APACHE).