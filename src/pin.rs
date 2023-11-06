use std::slice;

use crate::raw;

/// Upper bound on accepted PIN lengths; anything larger is a caller bug and
/// must not drive an allocation.
const MAX_PIN_LENGTH: raw::CK_ULONG = 4096;

// todo: securely store the pin
#[derive(Eq, PartialEq)]
pub struct Pin(String);

impl Pin {
    #[cfg(test)]
    pub fn new(pin: impl Into<String>) -> Self {
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
}
