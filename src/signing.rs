use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use hmac::Hmac;
use hmac::Mac;
use p256::ecdsa;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1v15;
use rsa::sha2::Sha256;
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;

use crate::operation::Operation;

pub type HmacSha256 = Hmac<Sha256>;

/// Length in bytes of an AES-GCM authentication tag.
pub const AES_GCM_TAG_LENGTH: usize = 16;

pub struct Signature(pub Vec<u8>);

pub trait Sign {
    fn sign(self, data: &[u8]) -> Signature;
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

impl Sign for Operation {
    fn sign(self, data: &[u8]) -> Signature {
        match self {
            Operation::SignRsa { private_key } => {
                let signing_key = pkcs1v15::SigningKey::<Sha256>::new(*private_key);
                let mut rng = rand::thread_rng();
                let signature = signing_key.sign_with_rng(&mut rng, data);
                Signature(signature.to_bytes().to_vec())
            }
            Operation::SignEcdsa { signing_key } => {
                let (signature, _) = signing_key.sign_prehash_recoverable(data).unwrap();
                Signature(signature.to_bytes().to_vec())
            }
            Operation::SignSha256Hmac { mut signing_key } => {
                signing_key.update(data);
                let signature = signing_key.finalize().into_bytes();
                Signature(signature.to_vec())
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
            Operation::VerifyRsa { public_key } => {
                let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(*public_key);
                pkcs1v15::Signature::try_from(signature)
                    .map(|signature| verifying_key.verify(data, &signature).is_ok())
                    .unwrap_or(false)
            }
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
                let nonce = Nonce::from_slice(&initialization_vector);
                let payload = Payload {
                    msg: data,
                    aad: &additional_authenticated_data,
                };

                match key.len() {
                    16 => Aes128Gcm::new_from_slice(&key).ok()?.encrypt(nonce, payload).ok(),
                    32 => Aes256Gcm::new_from_slice(&key).ok()?.encrypt(nonce, payload).ok(),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
