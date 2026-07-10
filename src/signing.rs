use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::aes::cipher::consts::U32;
use aes_gcm::aes::Aes128;
use aes_gcm::aes::Aes256;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use aes_gcm::AesGcm;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use hmac::Hmac;
use hmac::Mac;
use p256::ecdsa;
use rsa::pkcs1v15;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use signature::hazmat::PrehashVerifier;

use crate::operation::Operation;

pub type HmacSha256 = Hmac<Sha256>;

/// Length in bytes of an AES-GCM authentication tag.
pub const AES_GCM_TAG_LENGTH: usize = 16;

/// AES-GCM with a 32-byte initialization vector. AES-GCM's nonce length is a
/// compile-time type parameter, so each supported IV length needs its own
/// concrete cipher type; the default `Aes*Gcm` aliases fix it at 12 bytes.
type Aes128Gcm32 = AesGcm<Aes128, U32>;
type Aes256Gcm32 = AesGcm<Aes256, U32>;

/// Encrypts under a concrete AES-GCM cipher. The nonce length must match the
/// cipher's `NonceSize` (callers dispatch on it), so a mismatch here is a
/// caller bug rather than an input error.
fn gcm_encrypt<C>(key: &[u8], nonce: &[u8], payload: Payload) -> Option<Vec<u8>>
where
    C: KeyInit + Aead,
{
    let cipher = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C::NonceSize>::try_from(nonce).ok()?;
    cipher.encrypt(&nonce, payload).ok()
}

/// Decrypts under a concrete AES-GCM cipher. A `None` result is an
/// authentication-tag mismatch (or a ciphertext shorter than the tag).
fn gcm_decrypt<C>(key: &[u8], nonce: &[u8], payload: Payload) -> Option<Vec<u8>>
where
    C: KeyInit + Aead,
{
    let cipher = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C::NonceSize>::try_from(nonce).ok()?;
    cipher.decrypt(&nonce, payload).ok()
}

pub struct Signature(pub Vec<u8>);

pub trait Sign {
    /// Signs `data`, or `None` when the input is unusable for the mechanism
    /// (e.g. raw RSA data longer than the modulus allows).
    fn sign(self, data: &[u8]) -> Option<Signature>;
}

pub trait SignatureLength {
    fn signature_length(&self) -> u64;
}

pub trait Verify {
    fn verify(self, data: &[u8], signature: &[u8]) -> bool;
}

pub trait Encrypt {
    fn encrypt(self, data: &[u8]) -> Option<Vec<u8>>;
}

pub trait Decrypt {
    fn decrypt(self, data: &[u8]) -> Option<Vec<u8>>;
}

impl Sign for Operation {
    fn sign(self, data: &[u8]) -> Option<Signature> {
        match self {
            // CKM_RSA_PKCS pads the input as given with PKCS#1 v1.5 block type
            // 01 and signs it directly — no hashing and no DigestInfo prefix
            // (that would be CKM_SHA256_RSA_PKCS). Fails if `data` is longer
            // than the modulus can pad.
            Operation::SignRsa { private_key } => private_key
                .sign(pkcs1v15::Pkcs1v15Sign::new_unprefixed(), data)
                .ok()
                .map(Signature),
            Operation::SignEcdsa { signing_key } => {
                let (signature, _) = signing_key.sign_prehash_recoverable(data);
                Some(Signature(signature.to_bytes().to_vec()))
            }
            Operation::SignSha256Hmac { mut signing_key } => {
                signing_key.update(data);
                let signature = signing_key.finalize().into_bytes();
                Some(Signature(signature.to_vec()))
            }
            _ => unimplemented!("operation not supported"),
        }
    }
}

impl SignatureLength for Operation {
    fn signature_length(&self) -> u64 {
        match self {
            Operation::SignRsa { private_key } => private_key.size() as u64,
            Operation::SignEcdsa { .. } => 64,
            Operation::SignSha256Hmac { .. } => 32,
            _ => unimplemented!("operation not supported"),
        }
    }
}

impl Verify for Operation {
    fn verify(self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            // Verifies the CKM_RSA_PKCS counterpart: the recovered padded block
            // must equal `data` as given, with no DigestInfo prefix.
            Operation::VerifyRsa { public_key } => public_key
                .verify(pkcs1v15::Pkcs1v15Sign::new_unprefixed(), data, signature)
                .is_ok(),
            // CKM_ECDSA verifies a message digest, so `data` must not be
            // hashed again (mirrors sign_prehash in the signing direction).
            Operation::VerifyEcdsa { verifying_key } => ecdsa::Signature::from_slice(signature)
                .map(|signature| verifying_key.verify_prehash(data, &signature).is_ok())
                .unwrap_or(false),
            Operation::VerifySha256Hmac { mut verifying_key } => {
                verifying_key.update(data);
                verifying_key.verify_slice(signature).is_ok()
            }
            _ => unimplemented!("operation not supported for verification"),
        }
    }
}

impl Encrypt for Operation {
    fn encrypt(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Operation::EncryptAesGcm {
                key,
                initialization_vector,
                additional_authenticated_data,
            } => {
                let payload = Payload {
                    msg: data,
                    aad: &additional_authenticated_data,
                };
                let iv = &initialization_vector;

                match (key.len(), iv.len()) {
                    (16, 12) => gcm_encrypt::<Aes128Gcm>(&key, iv, payload),
                    (32, 12) => gcm_encrypt::<Aes256Gcm>(&key, iv, payload),
                    (16, 32) => gcm_encrypt::<Aes128Gcm32>(&key, iv, payload),
                    (32, 32) => gcm_encrypt::<Aes256Gcm32>(&key, iv, payload),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl Decrypt for Operation {
    fn decrypt(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Operation::DecryptAesGcm {
                key,
                initialization_vector,
                additional_authenticated_data,
            } => {
                let payload = Payload {
                    msg: data,
                    aad: &additional_authenticated_data,
                };
                let iv = &initialization_vector;

                match (key.len(), iv.len()) {
                    (16, 12) => gcm_decrypt::<Aes128Gcm>(&key, iv, payload),
                    (32, 12) => gcm_decrypt::<Aes256Gcm>(&key, iv, payload),
                    (16, 32) => gcm_decrypt::<Aes128Gcm32>(&key, iv, payload),
                    (32, 32) => gcm_decrypt::<Aes256Gcm32>(&key, iv, payload),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
