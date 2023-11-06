use std::slice;

use crate::raw;

// todo: securely store the pin
#[derive(Eq, PartialEq)]
pub struct Pin(String);

impl Pin {
    pub unsafe fn from_raw_parts(pPin: raw::CK_UTF8CHAR_PTR, ulPinLen: raw::CK_ULONG) -> Option<Self> {
        unsafe {
            String::from_utf8(slice::from_raw_parts(pPin, ulPinLen as usize).into())
                .ok()
                .map(Self)
        }
    }
}
