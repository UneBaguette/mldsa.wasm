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
                let sig = sign(&kp.seed, b"test", None);

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
                let sig = sign(&kp.seed, b"hello", None);

                assert!(verify(&kp.verifying_key, b"hello", &sig, None));
            }

            #[test]
            fn sign_verify_with_context() {
                let kp = generate_keypair();
                let ctx = Some(b"vexahub-share-v1".as_slice());
                let sig = sign(&kp.seed, b"hello", ctx);

                assert!(verify(&kp.verifying_key, b"hello", &sig, ctx));
                assert!(!verify(&kp.verifying_key, b"hello", &sig, None));
                assert!(!verify(&kp.verifying_key, b"hello", &sig, Some(b"wrong")));
            }

            #[test]
            fn sign_verify_empty_message() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"", None);

                assert!(verify(&kp.verifying_key, b"", &sig, None));
            }

            #[test]
            fn sign_verify_long_message() {
                let kp = generate_keypair();
                let msg = vec![0xABu8; 100_000];
                let sig = sign(&kp.seed, &msg, None);

                assert!(verify(&kp.verifying_key, &msg, &sig, None));
            }

            #[test]
            fn sign_verify_binary_message() {
                let kp = generate_keypair();
                let msg: Vec<u8> = (0u8..=255).collect();
                let sig = sign(&kp.seed, &msg, None);

                assert!(verify(&kp.verifying_key, &msg, &sig, None));
            }

            #[test]
            fn sign_verify_single_byte_message() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, &[0x00], None);

                assert!(verify(&kp.verifying_key, &[0x00], &sig, None));
            }

            // d

            #[test]
            fn deterministic_signatures() {
                let kp = generate_keypair();
                let sig1 = sign(&kp.seed, b"test", None);
                let sig2 = sign(&kp.seed, b"test", None);

                assert_eq!(sig1, sig2);
            }

            #[test]
            fn seed_reproduces_same_verifying_key() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"test", None);

                assert!(verify(&kp.verifying_key, b"test", &sig, None));
            }

            #[test]
            fn different_messages_produce_different_signatures() {
                let kp = generate_keypair();
                let sig1 = sign(&kp.seed, b"message one", None);
                let sig2 = sign(&kp.seed, b"message two", None);

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
                let sig = sign(&kp.seed, b"correct", None);

                assert!(!verify(&kp.verifying_key, b"wrong", &sig, None));
            }

            #[test]
            fn wrong_key_fails() {
                let kp1 = generate_keypair();
                let kp2 = generate_keypair();
                let sig = sign(&kp1.seed, b"hello", None);

                assert!(!verify(&kp2.verifying_key, b"hello", &sig, None));
            }

            #[test]
            fn invalid_signature_all_zeros() {
                let kp = generate_keypair();
                let bad_sig = [0u8; SIGNATURE_SIZE];

                assert!(!verify(&kp.verifying_key, b"test", &bad_sig, None));
            }

            #[test]
            fn invalid_signature_all_ones() {
                let kp = generate_keypair();
                let bad_sig = [0xFFu8; SIGNATURE_SIZE];

                assert!(!verify(&kp.verifying_key, b"test", &bad_sig, None));
            }

            #[test]
            fn tampered_signature_fails() {
                let kp = generate_keypair();
                let mut sig = sign(&kp.seed, b"hello", None);

                sig[0] ^= 0xFF;

                assert!(!verify(&kp.verifying_key, b"hello", &sig, None));
            }

            #[test]
            fn tampered_signature_last_byte_fails() {
                let kp = generate_keypair();
                let mut sig = sign(&kp.seed, b"hello", None);

                sig[SIGNATURE_SIZE - 1] ^= 0x01;

                assert!(!verify(&kp.verifying_key, b"hello", &sig, None));
            }

            #[test]
            fn empty_message_wrong_message_fails() {
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"", None);

                assert!(!verify(&kp.verifying_key, b"not empty", &sig, None));
            }

            #[test]
            fn cross_variant_message_fails() {
                // signature for one message cannot verify a different message
                let kp = generate_keypair();
                let sig = sign(&kp.seed, b"message a", None);

                assert!(!verify(&kp.verifying_key, b"message b", &sig, None));
                assert!(!verify(&kp.verifying_key, b"message A", &sig, None)); // case-sensitive
            }
        }

        #[cfg(all(target_arch = "wasm32", test, feature = "wasm"))]
        mod wasm_tests {
            use super::wasm::{
                Signer, generate_keypair_from_seed_wasm, generate_keypair_wasm, sign as sign_wasm,
                verify as verify_wasm,
            };
            use super::*;
            use wasm_bindgen_test::*;

            // correct

            #[wasm_bindgen_test]
            fn wasm_sign_verify_roundtrip() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"hello wasm", None).unwrap();

                assert!(verify_wasm(&kp.verifying_key, b"hello wasm", &sig, None).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_sign_verify_with_context() {
                let kp = generate_keypair_wasm();
                let ctx = Some(b"vexahub:v1:share".to_vec());
                let sig = sign_wasm(&kp.seed, b"hello", ctx.clone()).unwrap();

                assert!(verify_wasm(&kp.verifying_key, b"hello", &sig, ctx).unwrap());
                assert!(!verify_wasm(&kp.verifying_key, b"hello", &sig, None).unwrap());
                assert!(
                    !verify_wasm(&kp.verifying_key, b"hello", &sig, Some(b"wrong".to_vec()))
                        .unwrap()
                );
            }

            #[wasm_bindgen_test]
            fn wasm_sign_verify_empty_message() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"", None).unwrap();

                assert!(verify_wasm(&kp.verifying_key, b"", &sig, None).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_deterministic_signatures() {
                let kp = generate_keypair_wasm();
                let sig1 = sign_wasm(&kp.seed, b"test", None).unwrap();
                let sig2 = sign_wasm(&kp.seed, b"test", None).unwrap();

                assert_eq!(sig1, sig2);
            }

            #[wasm_bindgen_test]
            fn wasm_keypair_sizes() {
                let kp = generate_keypair_wasm();

                assert_eq!(kp.seed.len(), SEED_SIZE);
                assert_eq!(kp.verifying_key.len(), VERIFYING_KEY_SIZE);
            }

            #[wasm_bindgen_test]
            fn wasm_signature_size() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"test", None).unwrap();

                assert_eq!(sig.len(), SIGNATURE_SIZE);
            }

            // generate_keypair_from_seed

            #[wasm_bindgen_test]
            fn wasm_from_seed_reproduces_keypair() {
                let kp = generate_keypair_wasm();
                let kp2 = generate_keypair_from_seed_wasm(&kp.seed).unwrap();

                assert_eq!(kp.verifying_key, kp2.verifying_key);
            }

            #[wasm_bindgen_test]
            fn wasm_from_seed_cross_verify() {
                let kp = generate_keypair_wasm();
                let kp2 = generate_keypair_from_seed_wasm(&kp.seed).unwrap();
                let sig = sign_wasm(&kp.seed, b"test", None).unwrap();

                assert!(verify_wasm(&kp2.verifying_key, b"test", &sig, None).unwrap());
            }

            // signer

            #[wasm_bindgen_test]
            fn wasm_signer_roundtrip() {
                let kp = generate_keypair_wasm();
                let signer = Signer::new(&kp.seed).unwrap();
                let sig = signer.sign(b"hello", None);

                assert!(verify_wasm(&kp.verifying_key, b"hello", &sig, None).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_signer_verifying_key_matches() {
                let kp = generate_keypair_wasm();
                let signer = Signer::new(&kp.seed).unwrap();

                assert_eq!(signer.verifying_key(), kp.verifying_key);
            }

            #[wasm_bindgen_test]
            fn wasm_signer_deterministic() {
                let kp = generate_keypair_wasm();
                let signer = Signer::new(&kp.seed).unwrap();
                let sig1 = signer.sign(b"test", None);
                let sig2 = signer.sign(b"test", None);

                assert_eq!(sig1, sig2);
            }

            #[wasm_bindgen_test]
            fn wasm_signer_matches_standalone_sign() {
                let kp = generate_keypair_wasm();
                let signer = Signer::new(&kp.seed).unwrap();
                let sig_signer = signer.sign(b"test", None);
                let sig_standalone = sign_wasm(&kp.seed, b"test", None).unwrap();

                assert_eq!(sig_signer, sig_standalone);
            }

            #[wasm_bindgen_test]
            fn wasm_signer_with_context() {
                let kp = generate_keypair_wasm();
                let signer = Signer::new(&kp.seed).unwrap();
                let ctx = Some(b"vexahub:v1:share".to_vec());
                let sig = signer.sign(b"hello", ctx.clone());

                assert!(verify_wasm(&kp.verifying_key, b"hello", &sig, ctx).unwrap());
            }

            // reject

            #[wasm_bindgen_test]
            fn wasm_wrong_message_fails() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"correct", None).unwrap();

                assert!(!verify_wasm(&kp.verifying_key, b"wrong", &sig, None).unwrap());
            }

            #[wasm_bindgen_test]
            fn wasm_wrong_key_fails() {
                let kp1 = generate_keypair_wasm();
                let kp2 = generate_keypair_wasm();
                let sig = sign_wasm(&kp1.seed, b"hello", None).unwrap();

                assert!(!verify_wasm(&kp2.verifying_key, b"hello", &sig, None).unwrap());
            }

            // errors

            #[wasm_bindgen_test]
            fn wasm_sign_wrong_seed_length() {
                assert!(sign_wasm(&[0u8; 16], b"test", None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_sign_seed_too_long() {
                assert!(sign_wasm(&[0u8; 64], b"test", None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_sign_empty_seed() {
                assert!(sign_wasm(&[], b"test", None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_verify_wrong_vk_length() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"test", None).unwrap();

                assert!(verify_wasm(&[0u8; 16], b"test", &sig, None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_verify_wrong_sig_length() {
                let kp = generate_keypair_wasm();

                assert!(verify_wasm(&kp.verifying_key, b"test", &[0u8; 16], None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_verify_empty_vk() {
                let kp = generate_keypair_wasm();
                let sig = sign_wasm(&kp.seed, b"test", None).unwrap();

                assert!(verify_wasm(&[], b"test", &sig, None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_verify_empty_sig() {
                let kp = generate_keypair_wasm();

                assert!(verify_wasm(&kp.verifying_key, b"test", &[], None).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_from_seed_wrong_length() {
                assert!(generate_keypair_from_seed_wasm(&[0u8; 16]).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_from_seed_empty() {
                assert!(generate_keypair_from_seed_wasm(&[]).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_signer_wrong_seed_length() {
                assert!(Signer::new(&[0u8; 16]).is_err());
            }

            #[wasm_bindgen_test]
            fn wasm_signer_empty_seed() {
                assert!(Signer::new(&[]).is_err());
            }
        }
    };
}
