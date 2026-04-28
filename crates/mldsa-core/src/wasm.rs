// Copyright (c) 2026-present Thomas <tom@unebaguette.fr>
// SPDX-License-Identifier: MIT OR Apache-2.0

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_fixed<const N: usize>(s: &str, context: &str) -> Result<[u8; N], JsError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| JsError::new(&format!("invalid base64 at {context}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new(&format!("{context} must be {N} bytes")))
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
pub struct GenerateKeypairResult {
    pub seed: String,
    #[serde(rename = "verifyingKey")]
    pub verifying_key: String,
}
