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
    DecryptAesGcm {
        key: Vec<u8>,
        initialization_vector: Vec<u8>,
        additional_authenticated_data: Vec<u8>,
    },
    EncryptAesEcb {
        key: Vec<u8>,
    },
    DecryptAesEcb {
        key: Vec<u8>,
    },
    EncryptAesCbc {
        key: Vec<u8>,
        initialization_vector: Vec<u8>,
        /// PKCS#7 padding (`CKM_AES_CBC_PAD`) vs none (`CKM_AES_CBC`).
        pad: bool,
    },
    DecryptAesCbc {
        key: Vec<u8>,
        initialization_vector: Vec<u8>,
        pad: bool,
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
        matches!(
            self,
            Operation::EncryptAesGcm { .. } | Operation::EncryptAesEcb { .. } | Operation::EncryptAesCbc { .. }
        )
    }

    pub fn is_decrypt(&self) -> bool {
        matches!(
            self,
            Operation::DecryptAesGcm { .. } | Operation::DecryptAesEcb { .. } | Operation::DecryptAesCbc { .. }
        )
    }
}
