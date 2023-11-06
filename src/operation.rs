use p256::ecdsa;

#[derive(Debug)]
pub enum Operation {
    SignRsa {
        signing_key: Box<rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>>,
    },
    VerifyRsa {
        verifying_key: Box<rsa::pkcs1v15::VerifyingKey<rsa::sha2::Sha256>>,
    },
    SignEcdsa {
        signing_key: Box<ecdsa::SigningKey>,
    },
    VerifyEcdsa {
        verifying_key: Box<ecdsa::VerifyingKey>,
    },
}
