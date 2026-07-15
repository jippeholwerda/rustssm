/// A parsed, validated mechanism. The FFI layer translates `CK_MECHANISM`
/// (including any parameter structs) into this type; domain code never sees
/// raw pointers.
#[derive(Debug)]
pub enum Mechanism {
    GenericSecretKeyGen,
    AesKeyGen,
    RsaPkcsKeyPairGen,
    EcKeyPairGen,
    RsaPkcs,
    Ecdsa,
    Sha256Hmac,
    AesKeyWrapPad,
    AesGcm {
        initialization_vector: Vec<u8>,
        additional_authenticated_data: Vec<u8>,
    },
    AesEcb,
    AesCbc {
        initialization_vector: Vec<u8>,
    },
    AesCbcPad {
        initialization_vector: Vec<u8>,
    },
}
