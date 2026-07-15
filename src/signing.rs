use hmac::Hmac;
use hmac::Mac;
use p256::ecdsa;
use rsa::pkcs1v15;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use signature::hazmat::PrehashVerifier;

use crate::operation::Operation;

pub type HmacSha256 = Hmac<Sha256>;

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
