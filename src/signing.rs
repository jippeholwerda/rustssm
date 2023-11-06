use p256::{ecdsa, ecdsa::signature::Signer};
use rsa::{
    pkcs1v15,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
};

use crate::operation::Operation;

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

impl Sign for Operation {
    fn sign(self, data: &[u8]) -> Signature {
        match self {
            Operation::SignRsa { signing_key } => {
                let mut rng = rand::thread_rng();
                let signature = signing_key.sign_with_rng(&mut rng, data);
                Signature(signature.to_bytes().to_vec())
            }
            Operation::SignEcdsa { signing_key } => {
                let signature: ecdsa::Signature = signing_key.sign(data);
                Signature(signature.to_bytes().to_vec())
            }
            _ => panic!("operation not supported"),
        }
    }
}

impl SignatureLength for Operation {
    fn signature_length(&self) -> u64 {
        match self {
            Operation::SignRsa { .. } => 128, // todo: determine from key
            Operation::SignEcdsa { .. } => 64,
            _ => panic!("operation not supported"),
        }
    }
}

impl Verify for Operation {
    fn verify(self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            Operation::VerifyRsa { verifying_key } => {
                let signature = pkcs1v15::Signature::try_from(signature).unwrap();
                let result = verifying_key.verify(data, &signature);
                result.is_ok()
            }
            Operation::VerifyEcdsa { verifying_key } => {
                let signature = ecdsa::Signature::from_slice(signature).unwrap();
                let result = verifying_key.verify(data, &signature);
                result.is_ok()
            }
            _ => panic!("operation not supported"),
        }
    }
}
