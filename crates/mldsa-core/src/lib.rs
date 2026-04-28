// Copyright (c) 2026-present Thomas <tom@unebaguette.fr>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod tests;

use ml_dsa::{
    EncodedVerifyingKey, KeyGen, MlDsaParams, Signature, VerifyingKey,
    signature::rand_core::UnwrapErr,
    signature::{Keypair, Verifier},
};
use zeroize::Zeroize;

pub struct KeyPair<const VK: usize> {
    pub seed: [u8; 32],
    pub verifying_key: [u8; VK],
}

impl<const VK: usize> Drop for KeyPair<VK> {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

pub fn generate_keypair<P, const VK: usize>() -> KeyPair<VK>
where
    P: KeyGen<KeyPair = ml_dsa::SigningKey<P>>,
    P: MlDsaParams,
{
    let mut rng = UnwrapErr(getrandom::SysRng);
    let kp = P::key_gen(&mut rng);
    let seed: [u8; 32] = kp.to_seed().into();
    let vk = kp.verifying_key().encode();

    let mut vk_bytes = [0u8; VK];

    vk_bytes.copy_from_slice(&vk);

    KeyPair {
        seed,
        verifying_key: vk_bytes,
    }
}

pub fn sign<P, const SIG: usize>(seed: &[u8; 32], message: &[u8]) -> [u8; SIG]
where
    P: KeyGen<KeyPair = ml_dsa::SigningKey<P>>,
    P: MlDsaParams,
{
    let seed_arr = ml_dsa::B32::from(*seed);
    let kp = P::from_seed(&seed_arr);
    let sig = kp.signing_key().sign_deterministic(message, &[]).unwrap();
    let encoded = sig.encode();
    let mut sig_bytes = [0u8; SIG];

    sig_bytes.copy_from_slice(&encoded);

    sig_bytes
}

pub fn verify<P, const VK: usize, const SIG: usize>(
    vk_bytes: &[u8; VK],
    message: &[u8],
    sig_bytes: &[u8; SIG],
) -> bool
where
    P: MlDsaParams,
{
    let vk_encoded = match EncodedVerifyingKey::<P>::try_from(vk_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let vk = VerifyingKey::<P>::decode(&vk_encoded);

    let sig = match Signature::<P>::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    vk.verify(message, &sig).is_ok()
}
