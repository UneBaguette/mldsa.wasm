// Copyright (c) 2026-present Thomas <tom@unebaguette.fr>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[macro_export]
macro_rules! wasm_mldsa {
    () => {
        #[cfg(feature = "wasm")]
        mod wasm {
            use super::*;
            use serde::{Deserialize, Serialize};
            use tsify::Tsify;
            use wasm_bindgen::prelude::*;
            use zeroize::Zeroize;

            /// Result of `generateKeypair`.
            /// The seed is a 32-byte random value generated via the system RNG.
            /// It deterministically derives the full ML-DSA keypair and must be stored
            /// securely. It is equivalent to a private key.
            #[derive(Serialize, Deserialize, Tsify)]
            #[tsify(into_wasm_abi)] // TODO: Remove once deprecated
            #[serde(rename_all = "camelCase")]
            pub struct GenerateKeypairResult {
                #[tsify(type = "Uint8Array")]
                pub seed: Vec<u8>,
                #[tsify(type = "Uint8Array")]
                pub verifying_key: Vec<u8>,
            }

            /// Generates a fresh ML-DSA keypair using the system RNG.
            ///
            /// # Warning
            /// The seed is returned to JS memory. You are responsible for
            /// zeroizing it after use. Prefer `Signer` when possible.
            #[wasm_bindgen(js_name = "generateKeypair")]
            pub fn generate_keypair_wasm() -> GenerateKeypairResult {
                let kp = super::generate_keypair();

                GenerateKeypairResult {
                    seed: kp.seed.to_vec(),
                    verifying_key: kp.verifying_key.to_vec(),
                }
            }

            /// Reproduces an ML-DSA keypair from an existing 32-byte seed.
            ///
            /// # Errors
            /// Throws if `seed` is not exactly 32 bytes.
            #[wasm_bindgen(js_name = "generateKeypairFromSeed")]
            pub fn generate_keypair_from_seed_wasm(
                seed: &[u8],
            ) -> Result<GenerateKeypairResult, JsError> {
                let seed_arr: [u8; SEED_SIZE] = seed
                    .try_into()
                    .map_err(|_| JsError::new("seed must be 32 bytes"))?;

                let kp = super::generate_keypair_from_seed(&seed_arr);

                Ok(GenerateKeypairResult {
                    seed: kp.seed.to_vec(),
                    verifying_key: kp.verifying_key.to_vec(),
                })
            }

            // XXX: For future tsify, don't use yet.
            // #[wasm_bindgen(js_name = "generateKeypair")]
            // pub fn generate_keypair_wasm() -> Result<tsify::Ts<GenerateKeypairResult>, JsError> {
            //     let kp = super::generate_keypair();
            //
            //     Ok(GenerateKeypairResult {
            //         seed: kp.seed.to_vec(),
            //         verifying_key: kp.verifying_key.to_vec(),
            //     }.into_ts()?)
            // }

            /// Signs a message using the seed directly.
            ///
            /// # Warning
            /// The seed is passed through JS memory on every call.
            /// Prefer `Signer` for repeated signing.
            ///
            /// # Errors
            /// Throws if `seed` is not exactly 32 bytes.
            #[wasm_bindgen]
            pub fn sign(
                seed: &[u8],
                message: &[u8],
                context: Option<Vec<u8>>,
            ) -> Result<Vec<u8>, JsError> {
                let seed_arr: [u8; SEED_SIZE] = seed
                    .try_into()
                    .map_err(|_| JsError::new("seed must be 32 bytes"))?;

                Ok(super::sign(&seed_arr, message, context.as_deref()).to_vec())
            }

            /// Verifies an ML-DSA signature.
            ///
            /// # Errors
            /// Throws if `vk` or `signature` have incorrect length.
            #[wasm_bindgen]
            pub fn verify(
                vk: &[u8],
                message: &[u8],
                signature: &[u8],
                context: Option<Vec<u8>>,
            ) -> Result<bool, JsError> {
                let vk_arr: [u8; VERIFYING_KEY_SIZE] = vk.try_into().map_err(|_| {
                    JsError::new(&format!(
                        "verifyingKey must be {} bytes",
                        VERIFYING_KEY_SIZE
                    ))
                })?;

                let sig_arr: [u8; SIGNATURE_SIZE] = signature.try_into().map_err(|_| {
                    JsError::new(&format!("signature must be {} bytes", SIGNATURE_SIZE))
                })?;

                Ok(super::verify(
                    &vk_arr,
                    message,
                    &sig_arr,
                    context.as_deref(),
                ))
            }

            /// A stateful ML-DSA signer that keeps the seed inside WASM memory.
            ///
            /// The seed is zeroized automatically when the signer is dropped.
            /// Unless using older browsers.
            #[wasm_bindgen]
            pub struct Signer {
                seed: [u8; SEED_SIZE],
                verifying_key: [u8; VERIFYING_KEY_SIZE],
            }

            #[wasm_bindgen]
            impl Signer {
                /// Creates a new Signer from a 32-byte seed.
                /// The keypair is derived internally from the seed.
                ///
                /// # Errors
                /// Throws if `seed` is not exactly 32 bytes.
                #[wasm_bindgen(constructor)]
                pub fn new(seed: &[u8]) -> Result<Self, JsError> {
                    let seed_arr: [u8; SEED_SIZE] = seed
                        .try_into()
                        .map_err(|_| JsError::new("seed must be 32 bytes"))?;

                    let kp = super::generate_keypair_from_seed(&seed_arr);

                    Ok(Signer {
                        seed: seed_arr,
                        verifying_key: kp.verifying_key,
                    })
                }

                /// Returns the verifying key (public key) as raw bytes.
                #[wasm_bindgen(js_name = "verifyingKey")]
                pub fn verifying_key(&self) -> Vec<u8> {
                    self.verifying_key.to_vec()
                }

                /// Signs a message and returns the signature bytes.
                /// An optional context byte string can be provided per the ML-DSA spec.
                pub fn sign(&self, message: &[u8], context: Option<Vec<u8>>) -> Vec<u8> {
                    super::sign(&self.seed, message, context.as_deref()).to_vec()
                }
            }

            impl Drop for Signer {
                fn drop(&mut self) {
                    self.seed.zeroize();
                }
            }
        }

        #[cfg(feature = "wasm")]
        pub use wasm::*;
    };
}
