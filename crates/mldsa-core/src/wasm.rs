// Copyright (c) 2026-present Thomas <tom@unebaguette.fr>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "wasm")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "wasm")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes a base64url (no-pad) string into a fixed-size byte array.
/// Returns a JsError if the string is not valid base64 or if the decoded
/// length does not match exactly N bytes.
#[cfg(feature = "wasm")]
pub fn decode_fixed<const N: usize>(s: &str, context: &str) -> Result<[u8; N], JsError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| JsError::new(&format!("invalid base64 at {context}")))?;

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new(&format!("{context} must be {N} bytes")))
}

/// Result of `generateKeypair`. Both fields are base64url (no-pad) encoded.
/// The seed is a 32-byte random value generated via the system RNG.
/// It deterministically derives the full ML-DSA keypair and must be stored
/// securely. It is equivalent to a private key.
#[cfg(feature = "wasm")]
#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)] // TODO: Remove once deprecated
pub struct GenerateKeypairResult {
    pub seed: String,
    #[serde(rename = "verifyingKey")]
    pub verifying_key: String,
}

#[macro_export]
macro_rules! wasm_mldsa {
    () => {
        #[cfg(feature = "wasm")]
        mod wasm {
            use super::*;
            use mldsa_core::wasm::{GenerateKeypairResult, decode_fixed, encode};
            use wasm_bindgen::prelude::*;
            use zeroize::Zeroize;

            /// Generates a fresh ML-DSA keypair using the system RNG.
            ///
            /// # Warning
            /// The seed is returned to JS memory. You are responsible for
            /// zeroizing it after use. Prefer `Signer` when possible.
            #[wasm_bindgen(js_name = "generateKeypair")]
            pub fn generate_keypair_wasm() -> GenerateKeypairResult {
                let kp = super::generate_keypair();

                GenerateKeypairResult {
                    seed: encode(&kp.seed),
                    verifying_key: encode(&kp.verifying_key),
                }
            }

            // XXX: For future tsify, don't use yet.
            // #[wasm_bindgen(js_name = "generateKeypair")]
            // pub fn generate_keypair_wasm() -> Result<tsify::Ts<GenerateKeypairResult>, JsError> {
            //     let kp = super::generate_keypair();
            //
            //     Ok(GenerateKeypairResult {
            //         seed: encode(&kp.seed),
            //         verifying_key: encode(&kp.verifying_key),
            //     }.into_ts()?)
            // }

            /// Signs a message using the seed directly.
            ///
            /// # Warning
            /// The seed is passed through JS memory on every call.
            /// Prefer `Signer` for repeated signing.
            ///
            /// # Errors
            /// Throws if `seed` is not valid base64url or not exactly 32 bytes.
            #[wasm_bindgen]
            pub fn sign(
                seed: &str,
                message: &[u8],
                context: Option<Vec<u8>>,
            ) -> Result<String, JsError> {
                let seed_bytes = decode_fixed::<SEED_SIZE>(seed, "seed")?;
                let ctx = context.as_deref();

                Ok(encode(&super::sign(&seed_bytes, message, ctx)))
            }

            /// Verifies an ML-DSA signature.
            ///
            /// # Errors
            /// Throws if `vk`, or `signature` are not valid base64url or have incorrect length.
            #[wasm_bindgen]
            pub fn verify(
                vk: &str,
                message: &[u8],
                signature: &str,
                context: Option<Vec<u8>>,
            ) -> Result<bool, JsError> {
                let vk_bytes = decode_fixed::<VERIFYING_KEY_SIZE>(vk, "verifyingKey")?;
                let sig_bytes = decode_fixed::<SIGNATURE_SIZE>(signature, "signature")?;
                let ctx = context.as_deref();

                Ok(super::verify(&vk_bytes, message, &sig_bytes, ctx))
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
                /// Creates a new Signer from a base64url-encoded seed.
                /// The keypair is derived internally from the seed.
                ///
                /// # Errors
                /// Throws if `seed` is not valid base64url or not exactly 32 bytes.
                #[wasm_bindgen(constructor)]
                pub fn new(seed: &str) -> Result<Self, JsError> {
                    let seed_bytes = decode_fixed::<SEED_SIZE>(seed, "seed")?;
                    let kp = super::generate_keypair_from_seed(&seed_bytes);

                    Ok(Signer {
                        seed: seed_bytes,
                        verifying_key: kp.verifying_key,
                    })
                }

                /// Returns the base64url-encoded verifying key (public key).
                #[wasm_bindgen(js_name = "verifyingKey")]
                pub fn verifying_key(&self) -> String {
                    encode(&self.verifying_key)
                }

                /// Signs a message and returns a base64url-encoded signature.
                /// An optional context byte string can be provided per the ML-DSA spec.
                pub fn sign(&self, message: &[u8], context: Option<Vec<u8>>) -> String {
                    let ctx = context.as_deref();

                    encode(&super::sign(&self.seed, message, ctx))
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
