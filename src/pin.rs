use std::slice;

use sha2::Digest;
use sha2::Sha256;

use crate::raw;
use crate::util::random_bytes;

/// Upper bound on accepted PIN lengths; anything larger is a caller bug and
/// must not drive an allocation.
const MAX_PIN_LENGTH: raw::CK_ULONG = 4096;

/// A plaintext PIN, held only transiently while a call is in flight.
pub struct Pin(String);

impl Pin {
    pub(crate) fn new(pin: impl Into<String>) -> Self {
        Self(pin.into())
    }

    pub unsafe fn from_raw_parts(pPin: raw::CK_UTF8CHAR_PTR, ulPinLen: raw::CK_ULONG) -> Option<Self> {
        if pPin.is_null() || ulPinLen > MAX_PIN_LENGTH {
            return None;
        }

        unsafe {
            String::from_utf8(slice::from_raw_parts(pPin, ulPinLen as usize).into())
                .ok()
                .map(Self)
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A PIN as persisted on disk: a random salt and the SHA-256 of the salt
/// concatenated with the PIN, encoded as `"<salt_hex>:<hash_hex>"`.
pub struct PinHash(String);

impl PinHash {
    const SALT_LENGTH: usize = 16;

    /// Hashes `pin` under a fresh random salt.
    pub fn from_pin(pin: &Pin) -> Self {
        let salt_hex = to_hex(&random_bytes(Self::SALT_LENGTH));
        let hash_hex = to_hex(&digest(&salt_hex, pin));
        Self(format!("{salt_hex}:{hash_hex}"))
    }

    /// Reconstructs a hash previously produced by [`Self::as_str`].
    pub fn from_stored(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether `pin` matches this hash.
    pub fn verify(&self, pin: &Pin) -> bool {
        match self.0.split_once(':') {
            Some((salt_hex, hash_hex)) => to_hex(&digest(salt_hex, pin)) == hash_hex,
            None => false,
        }
    }
}

fn digest(salt_hex: &str, pin: &Pin) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update(pin.as_bytes());
    hasher.finalize().into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::Pin;
    use super::PinHash;

    #[test]
    fn hash_verifies_correct_pin_and_rejects_others() {
        let hash = PinHash::from_pin(&Pin::new("1234"));

        assert!(hash.verify(&Pin::new("1234")));
        assert!(!hash.verify(&Pin::new("4321")));
        assert!(!hash.verify(&Pin::new("")));
    }

    #[test]
    fn hash_is_salted_and_not_plaintext() {
        let a = PinHash::from_pin(&Pin::new("1234"));
        let b = PinHash::from_pin(&Pin::new("1234"));

        // Distinct salts yield distinct encodings for the same PIN.
        assert_ne!(a.as_str(), b.as_str());
        assert!(!a.as_str().contains("1234"));
    }

    #[test]
    fn stored_hash_round_trips() {
        let hash = PinHash::from_pin(&Pin::new("secret"));
        let restored = PinHash::from_stored(hash.as_str().to_string());

        assert!(restored.verify(&Pin::new("secret")));
    }
}
