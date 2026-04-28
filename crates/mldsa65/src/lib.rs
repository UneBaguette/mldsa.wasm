// Copyright (c) 2026-present Thomas <tom@unebaguette.fr>
// SPDX-License-Identifier: MIT OR Apache-2.0

use ml_dsa::MlDsa65;
use mldsa_core::KeyPair as CoreKeyPair;

#[cfg(all(
    not(target_feature = "atomics"),
    target_family = "wasm",
    feature = "talc"
))]
#[global_allocator]
static TALC: talc::wasm::WasmDynamicTalc = talc::wasm::new_wasm_dynamic_allocator();

pub const SEED_SIZE: usize = 32;
pub const SIGNING_KEY_SIZE: usize = 4032;
pub const VERIFYING_KEY_SIZE: usize = 1952;
pub const SIGNATURE_SIZE: usize = 3309;

pub type KeyPair = CoreKeyPair<VERIFYING_KEY_SIZE>;

pub fn generate_keypair() -> KeyPair {
    mldsa_core::generate_keypair::<MlDsa65, VERIFYING_KEY_SIZE>()
}

pub fn sign(seed: &[u8; SEED_SIZE], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    mldsa_core::sign::<MlDsa65, SIGNATURE_SIZE>(seed, message)
}

pub fn verify(vk: &[u8; VERIFYING_KEY_SIZE], message: &[u8], sig: &[u8; SIGNATURE_SIZE]) -> bool {
    mldsa_core::verify::<MlDsa65, VERIFYING_KEY_SIZE, SIGNATURE_SIZE>(vk, message, sig)
}

#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use mldsa_core::wasm::{GenerateKeypairResult, decode_fixed, encode};
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair_wasm() -> GenerateKeypairResult {
        let kp = super::generate_keypair();

        GenerateKeypairResult {
            seed: encode(&kp.seed),
            verifying_key: encode(&kp.verifying_key),
        }
    }

    #[wasm_bindgen]
    pub fn sign(seed: &str, message: &[u8]) -> Result<String, JsError> {
        let seed_bytes = decode_fixed::<SEED_SIZE>(seed, "seed")?;

        Ok(encode(&super::sign(&seed_bytes, message)))
    }

    #[wasm_bindgen]
    pub fn verify(vk: &str, message: &[u8], signature: &str) -> Result<bool, JsError> {
        let vk_bytes = decode_fixed::<VERIFYING_KEY_SIZE>(vk, "verifyingKey")?;
        let sig_bytes = decode_fixed::<SIGNATURE_SIZE>(signature, "signature")?;

        Ok(super::verify(&vk_bytes, message, &sig_bytes))
    }
}

#[cfg(feature = "wasm")]
pub use wasm::*;

mldsa_core::test_mldsa!();
