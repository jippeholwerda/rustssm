use p256::ecdsa;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;

use crate::signing::HmacSha256;

#[derive(Debug)]
pub enum Operation {
    SignRsa {
        private_key: Box<RsaPrivateKey>,
    },
    VerifyRsa {
        public_key: Box<RsaPublicKey>,
    },
    SignEcdsa {
        signing_key: Box<ecdsa::SigningKey>,
    },
    VerifyEcdsa {
        verifying_key: Box<ecdsa::VerifyingKey>,
    },
    SignSha256Hmac {
        signing_key: Box<HmacSha256>,
    },
    VerifySha256Hmac {
        verifying_key: Box<HmacSha256>,
    },
    EncryptAesGcm {
        key: Vec<u8>,
        initialization_vector: Vec<u8>,
        additional_authenticated_data: Vec<u8>,
    },
}

impl Operation {
    pub fn is_sign(&self) -> bool {
        matches!(
            self,
            Operation::SignRsa { .. } | Operation::SignEcdsa { .. } | Operation::SignSha256Hmac { .. }
        )
    }

    pub fn is_verify(&self) -> bool {
        matches!(
            self,
            Operation::VerifyRsa { .. } | Operation::VerifyEcdsa { .. } | Operation::VerifySha256Hmac { .. }
        )
    }

    pub fn is_encrypt(&self) -> bool {
        matches!(self, Operation::EncryptAesGcm { .. })
    }
}
