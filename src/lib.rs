use ml_dsa::signature::rand_core::UnwrapErr;
use ml_dsa::{
    KeyGen, MlDsa65, Signature,
    signature::{Keypair, Verifier},
};
use zeroize::Zeroize;

#[cfg(all(
    not(target_feature = "atomics"),
    target_family = "wasm",
    feature = "talc"
))]
#[global_allocator]
static TALC: talc::wasm::WasmDynamicTalc = talc::wasm::new_wasm_dynamic_allocator();

// ML-DSA-65 sizes
pub const SEED_SIZE: usize = 32;
pub const SIGNING_KEY_SIZE: usize = 4032;
pub const VERIFYING_KEY_SIZE: usize = 1952;
pub const SIGNATURE_SIZE: usize = 3309;

pub struct KeyPair {
    pub seed: [u8; SEED_SIZE],
    pub verifying_key: [u8; VERIFYING_KEY_SIZE],
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

pub fn generate_keypair() -> KeyPair {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = MlDsa65::key_gen(&mut rng);
    let seed = kp.to_seed();
    let vk = kp.verifying_key().encode();

    let mut seed_bytes = [0u8; SEED_SIZE];
    seed_bytes.copy_from_slice(&seed);
    let mut vk_bytes = [0u8; VERIFYING_KEY_SIZE];
    vk_bytes.copy_from_slice(&vk);

    KeyPair {
        seed: seed_bytes,
        verifying_key: vk_bytes,
    }
}

pub fn sign(seed: &[u8; SEED_SIZE], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let seed_arr = ml_dsa::B32::from(*seed);
    let kp = MlDsa65::from_seed(&seed_arr);
    let sig = kp.signing_key().sign_deterministic(message, &[]).unwrap();
    let encoded = sig.encode();
    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&encoded);

    sig_bytes
}

pub fn verify(
    vk_bytes: &[u8; VERIFYING_KEY_SIZE],
    message: &[u8],
    sig_bytes: &[u8; SIGNATURE_SIZE],
) -> bool {
    let vk_encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes.as_slice());
    let vk_encoded = match vk_encoded {
        Ok(v) => v,
        Err(_) => return false,
    };
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_encoded);
    let sig = match Signature::<MlDsa65>::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    vk.verify(message, &sig).is_ok()
}

#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Serialize};
    use tsify::Tsify;
    use wasm_bindgen::prelude::*;

    fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn decode(s: &str, context: &str) -> Result<Vec<u8>, JsError> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| JsError::new(&format!("invalid base64 at {context}")))
    }

    fn decode_fixed<const N: usize>(s: &str, context: &str) -> Result<[u8; N], JsError> {
        let bytes = decode(s, context)?;

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

    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair_wasm() -> GenerateKeypairResult {
        let kp = generate_keypair();

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
    pub fn verify(verifying_key: &str, message: &[u8], signature: &str) -> Result<bool, JsError> {
        let vk_bytes = decode_fixed::<VERIFYING_KEY_SIZE>(verifying_key, "verifyingKey")?;
        let sig_bytes = decode_fixed::<SIGNATURE_SIZE>(signature, "signature")?;

        Ok(super::verify(&vk_bytes, message, &sig_bytes))
    }
}

#[cfg(feature = "wasm")]
pub use wasm::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sizes() {
        let kp = generate_keypair();

        assert_eq!(kp.seed.len(), SEED_SIZE);
        assert_eq!(kp.verifying_key.len(), VERIFYING_KEY_SIZE);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = generate_keypair();
        let msg = b"hello vexahub";
        let sig = sign(&kp.seed, msg);

        assert!(verify(&kp.verifying_key, msg, &sig));
    }

    #[test]
    fn signature_size() {
        let kp = generate_keypair();
        let sig = sign(&kp.seed, b"test");

        assert_eq!(sig.len(), SIGNATURE_SIZE);
    }

    #[test]
    fn wrong_message_fails() {
        let kp = generate_keypair();
        let sig = sign(&kp.seed, b"correct message");

        assert!(!verify(&kp.verifying_key, b"wrong message", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let sig = sign(&kp1.seed, b"hello");

        assert!(!verify(&kp2.verifying_key, b"hello", &sig));
    }

    #[test]
    fn deterministic_signatures() {
        let kp = generate_keypair();
        let msg = b"deterministic test";
        let sig1 = sign(&kp.seed, msg);
        let sig2 = sign(&kp.seed, msg);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_messages_different_signatures() {
        let kp = generate_keypair();
        let sig1 = sign(&kp.seed, b"message one");
        let sig2 = sign(&kp.seed, b"message two");

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn invalid_verifying_key_returns_false() {
        let kp = generate_keypair();
        let sig = sign(&kp.seed, b"test");
        let bad_vk = [0u8; VERIFYING_KEY_SIZE];

        assert!(!verify(&bad_vk, b"test", &sig));
    }

    #[test]
    fn invalid_signature_returns_false() {
        let kp = generate_keypair();
        let bad_sig = [0u8; SIGNATURE_SIZE];

        assert!(!verify(&kp.verifying_key, b"test", &bad_sig));
    }

    #[test]
    fn empty_message() {
        let kp = generate_keypair();
        let sig = sign(&kp.seed, b"");

        assert!(verify(&kp.verifying_key, b"", &sig));
    }

    #[test]
    fn seed_reproduces_same_verifying_key() {
        let kp = generate_keypair();
        let seed_arr = ml_dsa::B32::from(kp.seed);
        let kp2 = MlDsa65::from_seed(&seed_arr);
        let mut vk_bytes = [0u8; VERIFYING_KEY_SIZE];

        vk_bytes.copy_from_slice(&kp2.verifying_key().encode());

        assert_eq!(kp.verifying_key, vk_bytes);
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod wasm_tests {
    use super::wasm::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn wasm_sign_verify_roundtrip() {
        let kp = generate_keypair_wasm();
        let sig = sign(&kp.seed, b"hello wasm").unwrap();

        assert!(verify(&kp.verifying_key, b"hello wasm", &sig).unwrap());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_message_fails() {
        let kp = generate_keypair_wasm();
        let sig = sign(&kp.seed, b"correct").unwrap();

        assert!(!verify(&kp.verifying_key, b"wrong", &sig).unwrap());
    }

    #[wasm_bindgen_test]
    fn wasm_invalid_seed_base64() {
        assert!(sign("not-valid!!!", b"test").is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_wrong_seed_length() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let short = URL_SAFE_NO_PAD.encode(&[0u8; 16]);

        assert!(sign(&short, b"test").is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_invalid_vk_base64() {
        let kp = generate_keypair_wasm();
        let sig = sign(&kp.seed, b"test").unwrap();

        assert!(verify("bad-base64!!!", b"test", &sig).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_invalid_sig_base64() {
        let kp = generate_keypair_wasm();

        assert!(verify(&kp.verifying_key, b"test", "bad-sig!!!").is_err());
    }
}
