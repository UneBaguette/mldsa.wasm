// Copyright (c) 2026-present Thomas <tom@unebaguette.fr>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[macro_export]
macro_rules! test_mldsa {
    () => {
        #[cfg(test)]
        mod tests {
            use super::*;

            // size

            #[test]
            fn keypair_sizes() {
                let kp = generate_keypair();

                assert_eq!(kp.seed.len(), SEED_SIZE);
                assert_eq!(kp.verifying_key.len(), VERIFYING_KEY_SIZE);
            }

            #[test]
            fn signature_size() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"test");

                assert_eq!(sig.len(), SIGNATURE_SIZE);
            }

            #[test]
            fn seed_size_is_32() {
                assert_eq!(SEED_SIZE, 32);
            }

            #[test]
            fn constants_are_nonzero() {
                assert!(SEED_SIZE > 0);
                assert!(SIGNING_KEY_SIZE > 0);
                assert!(VERIFYING_KEY_SIZE > 0);
                assert!(SIGNATURE_SIZE > 0);
            }

            // correct

            #[test]
            fn sign_verify_roundtrip() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"hello");

                assert!(verify(&kp.verifying_key, b"hello", &sig));
            }

            #[test]
            fn sign_verify_empty_message() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"");

                assert!(verify(&kp.verifying_key, b"", &sig));
            }

            #[test]
            fn sign_verify_long_message() {
                let kp = generate_keypair();
                let msg = vec![0xABu8; 100_000];
                let sig = sign(&kp.seed, &msg);

                assert!(verify(&kp.verifying_key, &msg, &sig));
            }

            #[test]
            fn sign_verify_binary_message() {
                let kp = generate_keypair();
                let msg: Vec<u8> = (0u8..=255).collect();
                let sig = sign(&kp.seed, &msg);

                assert!(verify(&kp.verifying_key, &msg, &sig));
            }

            #[test]
            fn sign_verify_single_byte_message() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, &[0x00]);

                assert!(verify(&kp.verifying_key, &[0x00], &sig));
            }

            // d

            #[test]
            fn deterministic_signatures() {
                let kp = generate_keypair();
                let sig1 = sign(&kp.seed, b"test");
                let sig2 = sign(&kp.seed, b"test");

                assert_eq!(sig1, sig2);
            }

            #[test]
            fn seed_reproduces_same_verifying_key() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"test");

                assert!(verify(&kp.verifying_key, b"test", &sig));
            }

            #[test]
            fn different_messages_produce_different_signatures() {
                let kp = generate_keypair();
                let sig1 = sign(&kp.seed, b"message one");
                let sig2 = sign(&kp.seed, b"message two");

                assert_ne!(sig1, sig2);
            }

            #[test]
            fn different_seeds_produce_different_keypairs() {
                let kp1 = generate_keypair();
                let kp2 = generate_keypair();

                assert_ne!(kp1.seed, kp2.seed);
                assert_ne!(kp1.verifying_key, kp2.verifying_key);
            }

            // reject

            #[test]
            fn wrong_message_fails() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"correct");

                assert!(!verify(&kp.verifying_key, b"wrong", &sig));
            }

            #[test]
            fn wrong_key_fails() {
                let kp1 = generate_keypair();
                let kp2 = generate_keypair();
                let sig = sign(&kp1.seed, b"hello");

                assert!(!verify(&kp2.verifying_key, b"hello", &sig));
            }

            #[test]
            fn invalid_signature_all_zeros() {
                let kp = generate_keypair();
                let bad_sig = [0u8; SIGNATURE_SIZE];

                assert!(!verify(&kp.verifying_key, b"test", &bad_sig));
            }

            #[test]
            fn invalid_signature_all_ones() {
                let kp = generate_keypair();
                let bad_sig = [0xFFu8; SIGNATURE_SIZE];

                assert!(!verify(&kp.verifying_key, b"test", &bad_sig));
            }

            #[test]
            fn tampered_signature_fails() {
                let kp = generate_keypair();
                let mut sig = sign(&kp.seed, b"hello");

                sig[0] ^= 0xFF;

                assert!(!verify(&kp.verifying_key, b"hello", &sig));
            }

            #[test]
            fn tampered_signature_last_byte_fails() {
                let kp = generate_keypair();
                let mut sig = sign(&kp.seed, b"hello");

                sig[SIGNATURE_SIZE - 1] ^= 0x01;

                assert!(!verify(&kp.verifying_key, b"hello", &sig));
            }

            #[test]
            fn empty_message_wrong_message_fails() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"");

                assert!(!verify(&kp.verifying_key, b"not empty", &sig));
            }

            #[test]
            fn cross_variant_message_fails() {
                // signature for one message cannot verify a different message
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"message a");

                assert!(!verify(&kp.verifying_key, b"message b", &sig));
                assert!(!verify(&kp.verifying_key, b"message A", &sig)); // case-sensitive
            }
        }

        #[cfg(all(target_arch = "wasm32", test, feature = "wasm"))]
        mod wasm_tests {
            use super::wasm::{generate_keypair_wasm, sign as sign_wasm, verify as verify_wasm};
            use wasm_bindgen_test::*;

            // correct

            #[wasm_bindgen_test]
            fn wasm_sign_verify_roundtrip() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"hello wasm").unwrap();
                assert!(verify_wasm(&kp.verifying_key, b"hello wasm", &sig).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_sign_verify_empty_message() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"").unwrap();
                assert!(verify_wasm(&kp.verifying_key, b"", &sig).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_deterministic_signatures() {
                let kp = generate_keypair_wasm();
                let sig1 = sign_wasm(&kp.seed, b"test").unwrap();
                let sig2 = sign_wasm(&kp.seed, b"test").unwrap();
                assert_eq!(sig1, sig2);
            }

            // reject

            #[wasm_bindgen_test]
            fn wasm_wrong_message_fails() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"correct").unwrap();
                assert!(!verify_wasm(&kp.verifying_key, b"wrong", &sig).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_wrong_key_fails() {
                let kp1 = generate_keypair_wasm();
                let kp2 = generate_keypair_wasm();
                let sig = sign_wasm(&kp1.seed, b"hello").unwrap();
                assert!(!verify_wasm(&kp2.verifying_key, b"hello", &sig).unwrap());
            }

            // errors!

            #[wasm_bindgen_test]
            fn wasm_invalid_seed_base64() {
                assert!(sign_wasm("not-valid!!!", b"test").is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_wrong_seed_length() {
                use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                let short = URL_SAFE_NO_PAD.encode(&[0u8; 16]);
                assert!(sign_wasm(&short, b"test").is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_seed_too_long() {
                use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                let long = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
                assert!(sign_wasm(&long, b"test").is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_invalid_vk_base64() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"test").unwrap();
                assert!(verify_wasm("bad!!!", b"test", &sig).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_invalid_sig_base64() {
                let kp = generate_keypair_wasm();
                assert!(verify_wasm(&kp.verifying_key, b"test", "bad!!!").is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_wrong_vk_length() {
                use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"test").unwrap();
                let short_vk = URL_SAFE_NO_PAD.encode(&[0u8; 16]);
                assert!(verify_wasm(&short_vk, b"test", &sig).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_wrong_sig_length() {
                use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                let kp = generate_keypair_wasm();
                let short_sig = URL_SAFE_NO_PAD.encode(&[0u8; 16]);
                assert!(verify_wasm(&kp.verifying_key, b"test", &short_sig).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_empty_string_seed_fails() {
                assert!(sign_wasm("", b"test").is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_empty_string_vk_fails() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"test").unwrap();
                assert!(verify_wasm("", b"test", &sig).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_empty_string_sig_fails() {
                let kp = generate_keypair_wasm();
                assert!(verify_wasm(&kp.verifying_key, b"test", "").is_err());
            }
        }
    };
}
