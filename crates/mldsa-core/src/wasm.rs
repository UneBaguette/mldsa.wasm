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

            #[wasm_bindgen]
            pub struct Signer {
                seed: [u8; SEED_SIZE],
                verifying_key: [u8; VERIFYING_KEY_SIZE],
            }

            #[wasm_bindgen]
            impl Signer {
                #[wasm_bindgen(constructor)]
                pub fn new(seed: &str) -> Result<Signer, JsError> {
                    let seed_bytes = decode_fixed::<SEED_SIZE>(seed, "seed")?;
                    let kp = super::generate_keypair_from_seed(&seed_bytes);

                    Ok(Signer {
                        seed: seed_bytes,
                        verifying_key: kp.verifying_key,
                    })
                }

                #[wasm_bindgen(js_name = "verifyingKey")]
                pub fn verifying_key(&self) -> String {
                    encode(&self.verifying_key)
                }

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
