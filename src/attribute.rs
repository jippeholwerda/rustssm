use std::collections::HashSet;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

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

    /// A recognized attribute type that rustssm does not model and silently
    /// ignores when it appears in a template (e.g. `CKA_MODIFIABLE`).
    Unknown,

    /// A token-managed, read-only attribute (e.g. `CKA_UNIQUE_ID`) that a
    /// client must not supply. Following SoftHSM, rustssm does not support
    /// these, so their presence in a creation/generation template is rejected
    /// rather than ignored.
    Unsupported,
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
            Attribute::Unknown | Attribute::Unsupported => return None,
        })
    }
}

/// Attribute types that can be requested through `C_GetAttributeValue`. Each
/// corresponds to exactly one [`Attribute`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Rejection of an application-supplied attribute template. The domain layer
/// (`hsm.rs`) maps each variant onto an `HsmError` in one place
/// (`template_error`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TemplateError {
    /// The template carries a token-managed, read-only attribute
    /// (`CKA_UNIQUE_ID` and friends, parsed as [`Attribute::Unsupported`]).
    /// Following SoftHSM, supplying one is a type error rather than a silent
    /// no-op.
    #[error("template carries a token-managed read-only attribute")]
    UnsupportedAttribute,

    /// The template carries the same attribute type more than once. PKCS#11
    /// leaves duplicate handling to the token; rustssm treats any repetition
    /// as inconsistent so readback and search stay single-valued.
    #[error("template carries an attribute type more than once")]
    DuplicateAttributeType,
}

/// An application-supplied attribute template that passed validation: it
/// carries no token-managed read-only attribute and no duplicate attribute
/// types.
///
/// Parse-don't-validate: [`Template::merge`] is the only producer of
/// [`CanonicalAttributes`], which in turn is the only attribute list a session
/// will persist — so an object-creating path that skips validation or the
/// merge does not compile, rather than silently storing an unnormalized list.
#[derive(Debug)]
pub struct Template(Vec<Attribute>);

impl Template {
    pub fn new(attributes: Vec<Attribute>) -> Result<Self, TemplateError> {
        if attributes.iter().any(|attr| matches!(attr, Attribute::Unsupported)) {
            return Err(TemplateError::UnsupportedAttribute);
        }

        // `Unknown`/`Unsupported` carry no attribute type and are skipped:
        // two distinct unrecognized attributes are not duplicates of each
        // other.
        let mut seen = HashSet::new();
        for attribute_type in attributes.iter().filter_map(Attribute::attribute_type) {
            if !seen.insert(attribute_type) {
                return Err(TemplateError::DuplicateAttributeType);
            }
        }

        Ok(Self(attributes))
    }

    pub fn attributes(&self) -> &[Attribute] {
        &self.0
    }

    /// The template's `CKA_CLASS`, when present.
    pub fn class(&self) -> Option<ObjectClass> {
        self.0.iter().find_map(|attr| match attr {
            Attribute::Class(class) => Some(*class),
            _ => None,
        })
    }

    /// Consumes a validated update list (`C_SetAttributeValue`-style
    /// overrides), which is applied to an existing object's stored attributes
    /// rather than merged into a creation template.
    pub fn into_vec(self) -> Vec<Attribute> {
        self.0
    }

    /// Merges token-synthesized/derived attributes into the template,
    /// producing the attribute list persisted with the object. `CKA_VALUE`
    /// (the key material) and unrecognized attributes are dropped; each
    /// derived attribute and each class default is added only when the
    /// template does not already carry that type, so the application's choice
    /// wins. Every boolean attribute the object's class defines ends up
    /// present, so `ObjectStore::search` stays a plain presence-plus-equality
    /// match (a template like `CKA_PRIVATE = false` matches an object whose
    /// template never mentioned it, as it would against SoftHSM).
    pub fn merge(self, derived: Vec<Attribute>) -> CanonicalAttributes {
        let Self(mut attributes) = self;
        attributes.retain(|attr| !matches!(attr, Attribute::Value(_) | Attribute::Unknown | Attribute::Unsupported));

        add_absent(&mut attributes, derived);

        // The class is now settled (from the template or the derived list),
        // so materialize the spec/token defaults for the boolean attributes
        // the template left unset.
        if let Some(class) = attributes.iter().find_map(|attr| match attr {
            Attribute::Class(class) => Some(*class),
            _ => None,
        }) {
            add_absent(&mut attributes, default_boolean_attributes(class));
        }

        CanonicalAttributes(attributes)
    }
}

/// An object's attribute list in canonical form — the creation template
/// merged with token-synthesized/derived attributes and class defaults.
/// Produced by [`Template::merge`] (the write path) or reconstructed from
/// the store, and the only list a session will persist.
#[derive(Debug)]
pub struct CanonicalAttributes(Vec<Attribute>);

impl CanonicalAttributes {
    /// Reconstructs the list of an already-persisted object — the store
    /// round-trip, or such a list after an attribute update. Not for
    /// application templates; those must go through [`Template::merge`].
    pub fn from_persisted(attributes: Vec<Attribute>) -> Self {
        Self(attributes)
    }

    #[allow(dead_code)]
    pub fn attributes(&self) -> &[Attribute] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<Attribute> {
        self.0
    }
}

/// Whether an object's stored `attributes` satisfy a search `template`: every
/// template attribute must be present with an equal value (an empty template
/// matches everything). Callers guard separately against templates carrying
/// [`Attribute::Unknown`], which must match nothing.
pub fn matches_template(template: &[Attribute], attributes: &[Attribute]) -> bool {
    template
        .iter()
        .all(|wanted| attributes.iter().any(|have| have == wanted))
}

/// Appends each of `additions` to `attributes` only if `attributes` does not
/// already carry an attribute of that type, so an application-supplied value
/// is never overwritten by a derived or default one.
fn add_absent(attributes: &mut Vec<Attribute>, additions: Vec<Attribute>) {
    for attribute in additions {
        let already_present = attribute.attribute_type().is_some_and(|type_| {
            attributes
                .iter()
                .any(|existing| existing.attribute_type() == Some(type_))
        });
        if !already_present {
            attributes.push(attribute);
        }
    }
}

/// The boolean-attribute defaults that are used at object creation when
/// the template omits them, keyed by object class. PKCS#11 fixes only
/// `CKA_TOKEN` and `CKA_DERIVE` (both false); the rest are token-specific, and
/// these are rustssm's documented choices — key material is private and
/// sensitive by default, and usage flags are opt-in (an application enables the
/// operations it needs). Applying these makes the stored attribute set complete
/// so search and readback behave like SoftHSM's.
pub(crate) fn default_boolean_attributes(class: ObjectClass) -> Vec<Attribute> {
    // `CKA_TOKEN` (session object) is common to every storage object.
    let mut defaults = vec![Attribute::Token(false), Attribute::Derive(false)];

    match class {
        ObjectClass::PublicKey => defaults.extend([
            Attribute::Private(false),
            Attribute::Encrypt(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
        ]),
        ObjectClass::PrivateKey => defaults.extend([
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Unwrap(false),
        ]),
        ObjectClass::SecretKey => defaults.extend([
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
        ]),
        // A classless object is degenerate (the creating path rejects unknown
        // classes); leave it as-is rather than guess a key's defaults.
        ObjectClass::Unknown => return Vec::new(),
    }

    defaults
}
