#[derive(Debug)]
pub enum Attribute {
    EcParams(Vec<u8>),
    Label(String),
    ModulusBits(u64),
    Private(bool),
    Token(bool),
    Class(ObjectClass),
    KeyType(KeyType),
    ValueLen(u64),
    Unknown,
}

/// Attribute types that can be read back through `C_GetAttributeValue`.
#[derive(Debug, Clone, Copy)]
pub enum AttributeType {
    EcPoint,
}

#[derive(Debug)]
pub enum ObjectClass {
    SecretKey,
    Unknown,
}
#[derive(Debug)]
pub enum KeyType {
    GenericSecret,
    Unknown,
}
