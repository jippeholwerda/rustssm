use serde::Deserialize;
use serde::Serialize;

/// A typed PKCS#11 object attribute. The FFI layer (`lib.rs`) owns the raw
/// `CKA_*` type codes and their byte encodings; the domain and the object
/// store only ever deal in these typed values, which are persisted verbatim
/// so they can be read back (`C_GetAttributeValue`) and matched against a
/// search template (`C_FindObjects`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attribute {
    Class(ObjectClass),
    KeyType(KeyType),

    Token(bool),
    Private(bool),
    Sensitive(bool),
    Extractable(bool),
    Derive(bool),
    Sign(bool),
    Verify(bool),
    Encrypt(bool),
    Decrypt(bool),
    Wrap(bool),
    Unwrap(bool),

    Label(String),
    Id(Vec<u8>),
    Value(Vec<u8>),
    ValueLen(u64),

    Modulus(Vec<u8>),
    ModulusBits(u64),
    PublicExponent(Vec<u8>),

    EcParams(Vec<u8>),
    EcPoint(Vec<u8>),

    Unknown,
}

impl Attribute {
    /// The attribute's type, used to look it up on readback and to compare it
    /// against a requested type. `Unknown` attributes have no readable type.
    pub fn attribute_type(&self) -> Option<AttributeType> {
        Some(match self {
            Attribute::Class(_) => AttributeType::Class,
            Attribute::KeyType(_) => AttributeType::KeyType,
            Attribute::Token(_) => AttributeType::Token,
            Attribute::Private(_) => AttributeType::Private,
            Attribute::Sensitive(_) => AttributeType::Sensitive,
            Attribute::Extractable(_) => AttributeType::Extractable,
            Attribute::Derive(_) => AttributeType::Derive,
            Attribute::Sign(_) => AttributeType::Sign,
            Attribute::Verify(_) => AttributeType::Verify,
            Attribute::Encrypt(_) => AttributeType::Encrypt,
            Attribute::Decrypt(_) => AttributeType::Decrypt,
            Attribute::Wrap(_) => AttributeType::Wrap,
            Attribute::Unwrap(_) => AttributeType::Unwrap,
            Attribute::Label(_) => AttributeType::Label,
            Attribute::Id(_) => AttributeType::Id,
            Attribute::Value(_) => AttributeType::Value,
            Attribute::ValueLen(_) => AttributeType::ValueLen,
            Attribute::Modulus(_) => AttributeType::Modulus,
            Attribute::ModulusBits(_) => AttributeType::ModulusBits,
            Attribute::PublicExponent(_) => AttributeType::PublicExponent,
            Attribute::EcParams(_) => AttributeType::EcParams,
            Attribute::EcPoint(_) => AttributeType::EcPoint,
            Attribute::Unknown => return None,
        })
    }
}

/// Attribute types that can be requested through `C_GetAttributeValue`. Each
/// corresponds to exactly one [`Attribute`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    Class,
    KeyType,
    Token,
    Private,
    Sensitive,
    Extractable,
    Derive,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Wrap,
    Unwrap,
    Label,
    Id,
    Value,
    ValueLen,
    Modulus,
    ModulusBits,
    PublicExponent,
    EcParams,
    EcPoint,
}

impl AttributeType {
    /// Whether `C_SetAttributeValue` may change this attribute. Identity and
    /// key-material attributes (class, key type, modulus, EC point, …) are
    /// fixed at creation; only usage/policy flags and the label/id can be
    /// updated.
    pub fn is_modifiable(&self) -> bool {
        matches!(
            self,
            AttributeType::Token
                | AttributeType::Private
                | AttributeType::Sensitive
                | AttributeType::Extractable
                | AttributeType::Derive
                | AttributeType::Sign
                | AttributeType::Verify
                | AttributeType::Encrypt
                | AttributeType::Decrypt
                | AttributeType::Wrap
                | AttributeType::Unwrap
                | AttributeType::Label
                | AttributeType::Id
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectClass {
    PublicKey,
    PrivateKey,
    SecretKey,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Rsa,
    Ec,
    Aes,
    GenericSecret,
    Unknown,
}
