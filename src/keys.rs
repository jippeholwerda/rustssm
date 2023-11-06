use crate::raw;

#[derive(Debug)]
pub struct PrivateKey(raw::CK_OBJECT_HANDLE);
