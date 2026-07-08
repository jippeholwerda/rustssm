#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//! PKCS#11 (Cryptoki) interface of the rustssm software HSM.
//!
//! # Architecture
//!
//! This file is a pure translation layer: it validates pointers, parses raw
//! PKCS#11 structures into typed values (`Mechanism`, `Attribute`, `Pin`),
//! implements the output-buffer conventions, and maps `HsmError` onto
//! `CK_RV` codes in one place (`rv_from`). All behavior lives in the domain
//! modules (`hsm`, `session`, `slot`, `object_store`), which never see raw
//! pointers or PKCS#11 codes and are unit-tested directly.
//!
//! # Error policy
//!
//! Every expected failure — invalid handle, bad template, unsupported
//! mechanism, database or crypto error — is returned as a `CK_RV` error
//! code. Panics are reserved for broken internal invariants and deliberately
//! abort the host process (crash-only): a software HSM that might be in an
//! inconsistent state must not keep signing. Consequently, any multi-step
//! state update performed under a lock must be panic-free.

use std::ptr;
use std::slice;
use std::sync::LazyLock;

use log::debug;
use log::warn;

use crate::attribute::Attribute;
use crate::attribute::AttributeType;
use crate::attribute::KeyType;
use crate::attribute::ObjectClass;
use crate::hsm::Hsm;
use crate::hsm::HsmError;
use crate::mechanism::Mechanism;
use crate::pin::Pin;
use crate::session::SessionId;
use crate::session::SessionState;
use crate::slot::SlotId;
use crate::slot::UserType;
use crate::util::padded;
use crate::util::random_bytes;

pub mod admin;
mod attribute;
mod hsm;
mod logging;
mod mechanism;
mod object_store;
mod operation;
mod pin;
mod raw;
mod session;
mod signing;
mod slot;
mod util;

static HSM: LazyLock<Hsm> = LazyLock::new(Hsm::default);

const MANUFACTURER: &str = "rustssm";
const LIBRARY_DESCRIPTION: &str = "rustssm software HSM";
const TOKEN_MODEL: &str = "rustssm";
const TOKEN_SERIAL: &str = "0000000000000001";

/// Bounds on caller-controlled sizes handled in this layer. Anything beyond
/// these is a caller bug and must not drive an allocation.
const MAX_RANDOM_LENGTH: raw::CK_ULONG = 1 << 20;
const MAX_WRAPPED_KEY_LENGTH: raw::CK_ULONG = 1 << 16;
const MAX_ATTRIBUTE_LENGTH: raw::CK_ULONG = 1 << 16;

type CkResult<T = ()> = Result<T, raw::CK_RV>;

/// Maps a domain error onto its PKCS#11 return value. The single place where
/// `HsmError` meets `CK_RV`.
fn rv_from(error: HsmError) -> raw::CK_RV {
    if let HsmError::ObjectStore(inner) = &error {
        warn!("object store failure: {inner}");
    }

    match error {
        HsmError::NotInitialized => raw::CKR_CRYPTOKI_NOT_INITIALIZED,
        HsmError::AlreadyInitialized => raw::CKR_CRYPTOKI_ALREADY_INITIALIZED,
        HsmError::SlotNotFound(_) => raw::CKR_SLOT_ID_INVALID,
        HsmError::SessionNotFound(_) => raw::CKR_SESSION_HANDLE_INVALID,
        HsmError::SessionExists(_) => raw::CKR_SESSION_EXISTS,
        HsmError::SessionReadOnly => raw::CKR_SESSION_READ_ONLY,
        HsmError::SessionReadOnlyExists => raw::CKR_SESSION_READ_ONLY_EXISTS,
        HsmError::UserAlreadyLoggedIn => raw::CKR_USER_ALREADY_LOGGED_IN,
        HsmError::UserAnotherAlreadyLoggedIn => raw::CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        HsmError::UserNotLoggedIn => raw::CKR_USER_NOT_LOGGED_IN,
        HsmError::UserPinNotInitialized => raw::CKR_USER_PIN_NOT_INITIALIZED,
        HsmError::PinIncorrect => raw::CKR_PIN_INCORRECT,
        HsmError::OperationActive => raw::CKR_OPERATION_ACTIVE,
        HsmError::OperationNotInitialized => raw::CKR_OPERATION_NOT_INITIALIZED,
        HsmError::MechanismInvalid => raw::CKR_MECHANISM_INVALID,
        HsmError::TemplateIncomplete => raw::CKR_TEMPLATE_INCOMPLETE,
        HsmError::TemplateInconsistent => raw::CKR_TEMPLATE_INCONSISTENT,
        HsmError::AttributeValueInvalid => raw::CKR_ATTRIBUTE_VALUE_INVALID,
        HsmError::AttributeTypeInvalid => raw::CKR_ATTRIBUTE_TYPE_INVALID,
        HsmError::AttributeReadOnly => raw::CKR_ATTRIBUTE_READ_ONLY,
        HsmError::KeyHandleInvalid => raw::CKR_KEY_HANDLE_INVALID,
        HsmError::KeySizeRange => raw::CKR_KEY_SIZE_RANGE,
        HsmError::WrappingKeyHandleInvalid => raw::CKR_WRAPPING_KEY_HANDLE_INVALID,
        HsmError::WrappingKeySizeRange => raw::CKR_WRAPPING_KEY_SIZE_RANGE,
        HsmError::UnwrappingKeyHandleInvalid => raw::CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        HsmError::UnwrappingKeySizeRange => raw::CKR_UNWRAPPING_KEY_SIZE_RANGE,
        HsmError::WrappedKeyInvalid => raw::CKR_WRAPPED_KEY_INVALID,
        HsmError::ObjectHandleInvalid => raw::CKR_OBJECT_HANDLE_INVALID,
        HsmError::SignatureInvalid => raw::CKR_SIGNATURE_INVALID,
        HsmError::DataLenRange => raw::CKR_DATA_LEN_RANGE,
        HsmError::EncryptedDataLenRange => raw::CKR_ENCRYPTED_DATA_LEN_RANGE,
        HsmError::EncryptedDataInvalid => raw::CKR_ENCRYPTED_DATA_INVALID,
        HsmError::ObjectStore(_) => raw::CKR_DEVICE_ERROR,
        HsmError::GeneralError => raw::CKR_GENERAL_ERROR,
    }
}

/// Runs `f` and converts its result to a `CK_RV`, logging non-OK returns.
fn ck<F>(name: &str, f: F) -> raw::CK_RV
where
    F: FnOnce() -> CkResult,
{
    match f() {
        Ok(()) => raw::CKR_OK,
        Err(rv) => {
            debug!("{name} returned 0x{rv:08x}");
            rv
        }
    }
}

trait ToCk<T> {
    fn ck(self) -> CkResult<T>;
}

impl<T> ToCk<T> for Result<T, HsmError> {
    fn ck(self) -> CkResult<T> {
        self.map_err(rv_from)
    }
}

/// Implements the PKCS#11 convention for functions returning variable-length
/// output: a null buffer requests the length, a too-small buffer yields
/// `CKR_BUFFER_TOO_SMALL`, and on success the actual length is stored.
unsafe fn write_output(data: &[u8], pOut: raw::CK_BYTE_PTR, pulOutLen: raw::CK_ULONG_PTR) -> CkResult {
    if pulOutLen.is_null() {
        return Err(raw::CKR_ARGUMENTS_BAD);
    }

    let required = data.len() as raw::CK_ULONG;
    if pOut.is_null() {
        *pulOutLen = required;
        return Ok(());
    }

    if *pulOutLen < required {
        *pulOutLen = required;
        return Err(raw::CKR_BUFFER_TOO_SMALL);
    }

    ptr::copy_nonoverlapping(data.as_ptr(), pOut, data.len());
    *pulOutLen = required;
    Ok(())
}

#[no_mangle]
pub extern "C" fn C_Initialize(_pInitArgs: raw::CK_VOID_PTR) -> raw::CK_RV {
    ck("C_Initialize", || {
        logging::init();
        debug!("C_Initialize");

        HSM.initialize().ck()
    })
}

#[no_mangle]
pub extern "C" fn C_Finalize(_pReserved: raw::CK_VOID_PTR) -> raw::CK_RV {
    ck("C_Finalize", || {
        debug!("C_Finalize");

        HSM.finalize().ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetInfo(pInfo: raw::CK_INFO_PTR) -> raw::CK_RV {
    ck("C_GetInfo", || {
        debug!("C_GetInfo");

        HSM.ensure_initialized().ck()?;
        if pInfo.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let info = raw::CK_INFO {
            cryptokiVersion: raw::CK_VERSION { major: 2, minor: 40 },
            manufacturerID: padded(MANUFACTURER),
            flags: 0,
            libraryDescription: padded(LIBRARY_DESCRIPTION),
            libraryVersion: raw::CK_VERSION { major: 0, minor: 1 },
        };

        unsafe {
            *pInfo = info;
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetSlotInfo(slotID: raw::CK_SLOT_ID, pInfo: raw::CK_SLOT_INFO_PTR) -> raw::CK_RV {
    ck("C_GetSlotInfo", || {
        debug!("C_GetSlotInfo for slot {}", slotID);

        HSM.slot_exists(SlotId(slotID)).ck()?;
        if pInfo.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let slot_info = raw::CK_SLOT_INFO {
            slotDescription: padded(&format!("rustssm slot {}", slotID)),
            manufacturerID: padded(MANUFACTURER),
            flags: raw::CKF_TOKEN_PRESENT,
            hardwareVersion: raw::CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: raw::CK_VERSION { major: 0, minor: 1 },
        };

        unsafe {
            *pInfo = slot_info;
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetTokenInfo(slotID: raw::CK_SLOT_ID, pInfo: raw::CK_TOKEN_INFO_PTR) -> raw::CK_RV {
    ck("C_GetTokenInfo", || {
        debug!("C_GetTokenInfo for slot {}", slotID);

        let status = HSM.token_status(SlotId(slotID)).ck()?;
        if pInfo.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let mut flags = raw::CKF_RNG;
        if status.initialized {
            flags |= raw::CKF_TOKEN_INITIALIZED;
        }
        if status.user_pin_set {
            flags |= raw::CKF_USER_PIN_INITIALIZED;
        }

        let token_info = raw::CK_TOKEN_INFO {
            label: padded(status.label.as_deref().unwrap_or("rustssm token")),
            manufacturerID: padded(MANUFACTURER),
            model: padded(TOKEN_MODEL),
            serialNumber: padded(TOKEN_SERIAL),
            flags,
            ulMaxSessionCount: raw::CK_EFFECTIVELY_INFINITE as raw::CK_ULONG,
            ulSessionCount: status.session_count as raw::CK_ULONG,
            ulMaxRwSessionCount: raw::CK_EFFECTIVELY_INFINITE as raw::CK_ULONG,
            ulRwSessionCount: raw::CK_UNAVAILABLE_INFORMATION,
            ulMaxPinLen: 255,
            ulMinPinLen: 4,
            ulTotalPublicMemory: raw::CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: raw::CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: raw::CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: raw::CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: raw::CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: raw::CK_VERSION { major: 0, minor: 1 },
            utcTime: padded(""),
        };

        unsafe {
            *pInfo = token_info;
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: raw::CK_BBOOL,
    pSlotList: raw::CK_SLOT_ID_PTR,
    pulCount: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    ck("C_GetSlotList", || {
        debug!("C_GetSlotList");

        // Every slot always has a (software) token present, so the
        // tokenPresent argument does not filter anything.
        let slot_ids = HSM.slot_ids().ck()?;
        if pulCount.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        unsafe {
            if pSlotList.is_null() {
                *pulCount = slot_ids.len() as raw::CK_ULONG;
                return Ok(());
            }

            if (*pulCount as usize) < slot_ids.len() {
                *pulCount = slot_ids.len() as raw::CK_ULONG;
                return Err(raw::CKR_BUFFER_TOO_SMALL);
            }

            ptr::copy_nonoverlapping(slot_ids.as_ptr(), pSlotList, slot_ids.len());
            *pulCount = slot_ids.len() as raw::CK_ULONG;
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_InitToken(
    slotID: raw::CK_SLOT_ID,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
    pLabel: raw::CK_UTF8CHAR_PTR,
) -> raw::CK_RV {
    ck("C_InitToken", || {
        debug!("C_InitToken for slot {}", slotID);

        let pin = unsafe { Pin::from_raw_parts(pPin, ulPinLen) }.ok_or(raw::CKR_PIN_INCORRECT)?;

        // The label is a fixed 32-byte field padded with spaces; it is not
        // NUL-terminated.
        let label = if pLabel.is_null() {
            None
        } else {
            let bytes = unsafe { slice::from_raw_parts(pLabel, 32) };
            Some(String::from_utf8_lossy(bytes).trim_end().to_string())
        };

        HSM.init_token(&SlotId(slotID), pin, label).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_OpenSession(
    slotID: raw::CK_SLOT_ID,
    flags: raw::CK_FLAGS,
    _pApplication: raw::CK_VOID_PTR,
    _Notify: raw::CK_NOTIFY,
    phSession: raw::CK_SESSION_HANDLE_PTR,
) -> raw::CK_RV {
    ck("C_OpenSession", || {
        debug!("C_OpenSession for slot {}", slotID);

        if phSession.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        if (flags & raw::CKF_SERIAL_SESSION) == 0 {
            return Err(raw::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }

        let state = if (flags & raw::CKF_RW_SESSION) == raw::CKF_RW_SESSION {
            SessionState::ReadWrite
        } else {
            SessionState::ReadOnly
        };

        let session_id = HSM.open_session(SlotId(slotID), state).ck()?;

        unsafe {
            *phSession = session_id.0;
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_CloseSession(hSession: raw::CK_SESSION_HANDLE) -> raw::CK_RV {
    ck("C_CloseSession", || {
        debug!("C_CloseSession session: {}", hSession);

        HSM.close_session(SessionId(hSession)).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: raw::CK_SESSION_HANDLE,
    pInfo: raw::CK_SESSION_INFO_PTR,
) -> raw::CK_RV {
    ck("C_GetSessionInfo", || {
        debug!("C_GetSessionInfo");

        let info = HSM.session_info(SessionId(hSession)).ck()?;
        if pInfo.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let state = match (info.read_write, info.user) {
            (true, Some(UserType::So)) => raw::CKS_RW_SO_FUNCTIONS,
            (true, Some(UserType::User)) => raw::CKS_RW_USER_FUNCTIONS,
            (true, None) => raw::CKS_RW_PUBLIC_SESSION,
            (false, Some(UserType::User)) => raw::CKS_RO_USER_FUNCTIONS,
            (false, _) => raw::CKS_RO_PUBLIC_SESSION,
        };

        let mut flags = raw::CKF_SERIAL_SESSION;
        if info.read_write {
            flags |= raw::CKF_RW_SESSION;
        }

        let session_info = raw::CK_SESSION_INFO {
            slotID: info.slot_id,
            state,
            flags,
            ulDeviceError: 0,
        };

        unsafe {
            *pInfo = session_info;
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_Login(
    hSession: raw::CK_SESSION_HANDLE,
    userType: raw::CK_USER_TYPE,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_Login", || {
        debug!("C_Login session: {}", hSession);

        let user_type = match userType {
            raw::CKU_SO => UserType::So,
            raw::CKU_USER => UserType::User,
            _ => return Err(raw::CKR_USER_TYPE_INVALID),
        };

        let pin = unsafe { Pin::from_raw_parts(pPin, ulPinLen) }.ok_or(raw::CKR_ARGUMENTS_BAD)?;

        HSM.login(SessionId(hSession), user_type, pin).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_LoginUser(
    hSession: raw::CK_SESSION_HANDLE,
    userType: raw::CK_USER_TYPE,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
    _pUsername: raw::CK_UTF8CHAR_PTR,
    _ulUsernameLen: raw::CK_ULONG,
) -> raw::CK_RV {
    debug!("C_LoginUser");

    C_Login(hSession, userType, pPin, ulPinLen)
}

#[no_mangle]
pub extern "C" fn C_Logout(hSession: raw::CK_SESSION_HANDLE) -> raw::CK_RV {
    ck("C_Logout", || {
        debug!("C_Logout session: {}", hSession);

        HSM.logout(SessionId(hSession)).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_InitPIN(
    hSession: raw::CK_SESSION_HANDLE,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_InitPIN", || {
        debug!("C_InitPIN");

        let pin = unsafe { Pin::from_raw_parts(pPin, ulPinLen) }.ok_or(raw::CKR_ARGUMENTS_BAD)?;

        HSM.init_pin(SessionId(hSession), pin).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_SetPIN(
    hSession: raw::CK_SESSION_HANDLE,
    pOldPin: raw::CK_UTF8CHAR_PTR,
    ulOldLen: raw::CK_ULONG,
    pNewPin: raw::CK_UTF8CHAR_PTR,
    ulNewLen: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_SetPIN", || {
        debug!("C_SetPIN");

        let old_pin = unsafe { Pin::from_raw_parts(pOldPin, ulOldLen) }.ok_or(raw::CKR_ARGUMENTS_BAD)?;
        let new_pin = unsafe { Pin::from_raw_parts(pNewPin, ulNewLen) }.ok_or(raw::CKR_ARGUMENTS_BAD)?;

        HSM.set_pin(SessionId(hSession), old_pin, new_pin).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GenerateKey(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    pTemplate: raw::CK_ATTRIBUTE_PTR,
    ulCount: raw::CK_ULONG,
    phKey: raw::CK_OBJECT_HANDLE_PTR,
) -> raw::CK_RV {
    ck("C_GenerateKey", || {
        debug!("C_GenerateKey");

        if phKey.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let mechanism = unsafe { read_mechanism(pMechanism) }?;
        let attributes = unsafe { read_attributes(pTemplate, ulCount) };
        debug!(
            "C_GenerateKey mechanism: {:?}, attributes: {:?}",
            &mechanism, &attributes
        );

        let object_id = HSM.generate_key(SessionId(hSession), &mechanism, attributes).ck()?;

        unsafe {
            *phKey = object_id.into();
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GenerateKeyPair(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    pPublicKeyTemplate: raw::CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: raw::CK_ULONG,
    pPrivateKeyTemplate: raw::CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: raw::CK_ULONG,
    phPublicKey: raw::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: raw::CK_OBJECT_HANDLE_PTR,
) -> raw::CK_RV {
    ck("C_GenerateKeyPair", || {
        debug!("C_GenerateKeyPair");

        if phPublicKey.is_null() || phPrivateKey.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let mechanism = unsafe { read_mechanism(pMechanism) }?;
        let public_key_attributes = unsafe { read_attributes(pPublicKeyTemplate, ulPublicKeyAttributeCount) };
        let private_key_attributes = unsafe { read_attributes(pPrivateKeyTemplate, ulPrivateKeyAttributeCount) };
        debug!(
            "C_GenerateKeyPair mechanism: {:?}, public attributes: {:?}, private attributes: {:?}",
            &mechanism, &public_key_attributes, &private_key_attributes
        );

        let (public_id, private_id) = HSM
            .generate_key_pair(
                SessionId(hSession),
                &mechanism,
                public_key_attributes,
                private_key_attributes,
            )
            .ck()?;

        unsafe {
            *phPublicKey = public_id.into();
            *phPrivateKey = private_id.into();
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_WrapKey(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hWrappingKey: raw::CK_OBJECT_HANDLE,
    hKey: raw::CK_OBJECT_HANDLE,
    pWrappedKey: raw::CK_BYTE_PTR,
    pulWrappedKeyLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    ck("C_WrapKey", || {
        debug!("C_WrapKey");

        let mechanism = unsafe { read_mechanism(pMechanism) }?;

        let wrapped_key = HSM
            .wrap_key(SessionId(hSession), &mechanism, hWrappingKey.into(), hKey.into())
            .ck()?;

        unsafe { write_output(&wrapped_key, pWrappedKey, pulWrappedKeyLen) }
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_UnwrapKey(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hUnwrappingKey: raw::CK_OBJECT_HANDLE,
    pWrappedKey: raw::CK_BYTE_PTR,
    ulWrappedKeyLen: raw::CK_ULONG,
    pTemplate: raw::CK_ATTRIBUTE_PTR,
    ulAttributeCount: raw::CK_ULONG,
    phKey: raw::CK_OBJECT_HANDLE_PTR,
) -> raw::CK_RV {
    ck("C_UnwrapKey", || {
        debug!("C_UnwrapKey");

        if pWrappedKey.is_null() || phKey.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        if ulWrappedKeyLen == 0 || ulWrappedKeyLen > MAX_WRAPPED_KEY_LENGTH {
            return Err(raw::CKR_WRAPPED_KEY_LEN_RANGE);
        }

        let mechanism = unsafe { read_mechanism(pMechanism) }?;
        let attributes = unsafe { read_attributes(pTemplate, ulAttributeCount) };
        let wrapped_key = unsafe { slice::from_raw_parts(pWrappedKey, ulWrappedKeyLen as usize) };

        let object_id = HSM
            .unwrap_key(
                SessionId(hSession),
                &mechanism,
                hUnwrappingKey.into(),
                wrapped_key,
                attributes,
            )
            .ck()?;

        unsafe {
            *phKey = object_id.into();
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_SignInit(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hKey: raw::CK_OBJECT_HANDLE,
) -> raw::CK_RV {
    ck("C_SignInit", || {
        debug!("C_SignInit");

        let mechanism = unsafe { read_mechanism(pMechanism) }?;

        HSM.sign_init(SessionId(hSession), &mechanism, hKey.into()).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_Sign(
    hSession: raw::CK_SESSION_HANDLE,
    pData: raw::CK_BYTE_PTR,
    ulDataLen: raw::CK_ULONG,
    pSignature: raw::CK_BYTE_PTR,
    pulSignatureLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    ck("C_Sign", || {
        debug!("C_Sign");

        let session_id = SessionId(hSession);
        let signature_length = HSM.signature_length(session_id).ck()?;

        if pData.is_null() || pulSignatureLen.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        unsafe {
            // A null signature buffer requests the length; a too-small buffer
            // is reported without consuming the operation.
            if pSignature.is_null() {
                *pulSignatureLen = signature_length;
                return Ok(());
            }

            if *pulSignatureLen < signature_length {
                *pulSignatureLen = signature_length;
                return Err(raw::CKR_BUFFER_TOO_SMALL);
            }

            let data = slice::from_raw_parts(pData, ulDataLen as usize);
            let signature = HSM.sign(session_id, data).ck()?;

            ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
            *pulSignatureLen = signature.len() as raw::CK_ULONG;
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_VerifyInit(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hKey: raw::CK_OBJECT_HANDLE,
) -> raw::CK_RV {
    ck("C_VerifyInit", || {
        debug!("C_VerifyInit");

        let mechanism = unsafe { read_mechanism(pMechanism) }?;

        HSM.verify_init(SessionId(hSession), &mechanism, hKey.into()).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_Verify(
    hSession: raw::CK_SESSION_HANDLE,
    pData: raw::CK_BYTE_PTR,
    ulDataLen: raw::CK_ULONG,
    pSignature: raw::CK_BYTE_PTR,
    ulSignatureLen: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_Verify", || {
        debug!("C_Verify");

        if pData.is_null() || pSignature.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        unsafe {
            let data = slice::from_raw_parts(pData, ulDataLen as usize);
            let signature = slice::from_raw_parts(pSignature, ulSignatureLen as usize);

            HSM.verify(SessionId(hSession), data, signature).ck()
        }
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_CreateObject(
    hSession: raw::CK_SESSION_HANDLE,
    pTemplate: raw::CK_ATTRIBUTE_PTR,
    ulCount: raw::CK_ULONG,
    phObject: raw::CK_OBJECT_HANDLE_PTR,
) -> raw::CK_RV {
    ck("C_CreateObject", || {
        debug!("C_CreateObject");

        if phObject.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let attributes = unsafe { read_attributes(pTemplate, ulCount) };
        debug!("C_CreateObject attributes: {:?}", &attributes);

        let object_id = HSM.create_object(SessionId(hSession), attributes).ck()?;

        unsafe {
            *phObject = object_id.into();
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_SetAttributeValue(
    hSession: raw::CK_SESSION_HANDLE,
    hObject: raw::CK_OBJECT_HANDLE,
    pTemplate: raw::CK_ATTRIBUTE_PTR,
    ulCount: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_SetAttributeValue", || {
        debug!("C_SetAttributeValue");

        if pTemplate.is_null() && ulCount > 0 {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let attributes = unsafe { read_attributes(pTemplate, ulCount) };
        debug!("C_SetAttributeValue attributes: {:?}", &attributes);

        // An unrecognized (untracked) attribute type parses as `Unknown`;
        // the domain rejects it as `CKR_ATTRIBUTE_TYPE_INVALID`.
        HSM.set_object_attributes(SessionId(hSession), hObject.into(), attributes)
            .ck()
    })
}

#[no_mangle]
pub extern "C" fn C_DestroyObject(hSession: raw::CK_SESSION_HANDLE, hObject: raw::CK_OBJECT_HANDLE) -> raw::CK_RV {
    ck("C_DestroyObject", || {
        debug!("C_DestroyObject");

        HSM.destroy_object(SessionId(hSession), hObject.into()).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_EncryptInit(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hKey: raw::CK_OBJECT_HANDLE,
) -> raw::CK_RV {
    ck("C_EncryptInit", || {
        debug!("C_EncryptInit");

        let mechanism = unsafe { read_mechanism(pMechanism) }?;

        HSM.encrypt_init(SessionId(hSession), &mechanism, hKey.into()).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_Encrypt(
    hSession: raw::CK_SESSION_HANDLE,
    pData: raw::CK_BYTE_PTR,
    ulDataLen: raw::CK_ULONG,
    pEncryptedData: raw::CK_BYTE_PTR,
    pulEncryptedDataLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    ck("C_Encrypt", || {
        debug!("C_Encrypt");

        let session_id = SessionId(hSession);
        let required = HSM.encrypted_length(session_id, ulDataLen).ck()?;

        if (pData.is_null() && ulDataLen > 0) || pulEncryptedDataLen.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        unsafe {
            // A null output buffer requests the length; a too-small buffer is
            // reported without consuming the operation.
            if pEncryptedData.is_null() {
                *pulEncryptedDataLen = required;
                return Ok(());
            }

            if *pulEncryptedDataLen < required {
                *pulEncryptedDataLen = required;
                return Err(raw::CKR_BUFFER_TOO_SMALL);
            }

            let data = if ulDataLen == 0 {
                &[]
            } else {
                slice::from_raw_parts(pData, ulDataLen as usize)
            };

            let ciphertext = HSM.encrypt(session_id, data).ck()?;

            ptr::copy_nonoverlapping(ciphertext.as_ptr(), pEncryptedData, ciphertext.len());
            *pulEncryptedDataLen = ciphertext.len() as raw::CK_ULONG;
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_EncryptUpdate(
    _hSession: raw::CK_SESSION_HANDLE,
    _pPart: raw::CK_BYTE_PTR,
    _ulPartLen: raw::CK_ULONG,
    _pEncryptedPart: raw::CK_BYTE_PTR,
    _pulEncryptedPartLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    debug!("C_EncryptUpdate");
    raw::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_EncryptFinal(
    _hSession: raw::CK_SESSION_HANDLE,
    _pLastEncryptedPart: raw::CK_BYTE_PTR,
    _pulLastEncryptedPartLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    debug!("C_EncryptFinal");
    raw::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_DecryptInit(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hKey: raw::CK_OBJECT_HANDLE,
) -> raw::CK_RV {
    ck("C_DecryptInit", || {
        debug!("C_DecryptInit");

        let mechanism = unsafe { read_mechanism(pMechanism) }?;

        HSM.decrypt_init(SessionId(hSession), &mechanism, hKey.into()).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_Decrypt(
    hSession: raw::CK_SESSION_HANDLE,
    pEncryptedData: raw::CK_BYTE_PTR,
    ulEncryptedDataLen: raw::CK_ULONG,
    pData: raw::CK_BYTE_PTR,
    pulDataLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    ck("C_Decrypt", || {
        debug!("C_Decrypt");

        let session_id = SessionId(hSession);
        let required = HSM.decrypted_length(session_id, ulEncryptedDataLen).ck()?;

        if pEncryptedData.is_null() || pulDataLen.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        unsafe {
            // A null output buffer requests the length; a too-small buffer is
            // reported without consuming the operation.
            if pData.is_null() {
                *pulDataLen = required;
                return Ok(());
            }

            if *pulDataLen < required {
                *pulDataLen = required;
                return Err(raw::CKR_BUFFER_TOO_SMALL);
            }

            let ciphertext = slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize);
            let plaintext = HSM.decrypt(session_id, ciphertext).ck()?;

            ptr::copy_nonoverlapping(plaintext.as_ptr(), pData, plaintext.len());
            *pulDataLen = plaintext.len() as raw::CK_ULONG;
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_DecryptUpdate(
    _hSession: raw::CK_SESSION_HANDLE,
    _pEncryptedPart: raw::CK_BYTE_PTR,
    _ulEncryptedPartLen: raw::CK_ULONG,
    _pPart: raw::CK_BYTE_PTR,
    _pulPartLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    debug!("C_DecryptUpdate");
    raw::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_DecryptFinal(
    _hSession: raw::CK_SESSION_HANDLE,
    _pLastPart: raw::CK_BYTE_PTR,
    _pulLastPartLen: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    debug!("C_DecryptFinal");
    raw::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_WaitForSlotEvent(
    flags: raw::CK_FLAGS,
    _pSlot: raw::CK_SLOT_ID_PTR,
    _pReserved: raw::CK_VOID_PTR,
) -> raw::CK_RV {
    ck("C_WaitForSlotEvent", || {
        debug!("C_WaitForSlotEvent");

        HSM.ensure_initialized().ck()?;

        if (flags & raw::CKF_DONT_BLOCK) != 0 {
            // A software token never produces slot events.
            Err(raw::CKR_NO_EVENT)
        } else {
            Err(raw::CKR_FUNCTION_NOT_SUPPORTED)
        }
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: raw::CK_SESSION_HANDLE,
    pTemplate: raw::CK_ATTRIBUTE_PTR,
    ulCount: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_FindObjectsInit", || {
        debug!("C_FindObjectsInit");

        let attributes = unsafe { read_attributes(pTemplate, ulCount) };

        HSM.find_objects_init(SessionId(hSession), attributes).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_FindObjects(
    hSession: raw::CK_SESSION_HANDLE,
    phObject: raw::CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: raw::CK_ULONG,
    pulObjectCount: raw::CK_ULONG_PTR,
) -> raw::CK_RV {
    ck("C_FindObjects", || {
        debug!("C_FindObjects");

        if phObject.is_null() || pulObjectCount.is_null() {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let found = HSM
            .find_objects_next(SessionId(hSession), ulMaxObjectCount as usize)
            .ck()?;

        unsafe {
            for (index, object_id) in found.iter().enumerate() {
                *phObject.add(index) = object_id.clone().into();
            }
            *pulObjectCount = found.len() as raw::CK_ULONG;
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(hSession: raw::CK_SESSION_HANDLE) -> raw::CK_RV {
    ck("C_FindObjectsFinal", || {
        debug!("C_FindObjectsFinal");

        HSM.find_objects_final(SessionId(hSession)).ck()
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_SeedRandom(
    hSession: raw::CK_SESSION_HANDLE,
    pSeed: raw::CK_BYTE_PTR,
    ulSeedLen: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_SeedRandom", || {
        debug!("C_SeedRandom");

        HSM.validate_session(SessionId(hSession)).ck()?;
        if pSeed.is_null() && ulSeedLen > 0 {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        // The OS random number generator cannot be seeded externally; the
        // seed is accepted and ignored.
        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GenerateRandom(
    hSession: raw::CK_SESSION_HANDLE,
    RandomData: raw::CK_BYTE_PTR,
    ulRandomLen: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_GenerateRandom", || {
        debug!("C_GenerateRandom");

        HSM.validate_session(SessionId(hSession)).ck()?;
        if (RandomData.is_null() && ulRandomLen > 0) || ulRandomLen > MAX_RANDOM_LENGTH {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        let data = random_bytes(ulRandomLen as usize);

        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), RandomData, data.len());
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: raw::CK_SESSION_HANDLE,
    hObject: raw::CK_OBJECT_HANDLE,
    pTemplate: raw::CK_ATTRIBUTE_PTR,
    ulCount: raw::CK_ULONG,
) -> raw::CK_RV {
    ck("C_GetAttributeValue", || {
        debug!("C_GetAttributeValue");

        let session_id = SessionId(hSession);

        if pTemplate.is_null() && ulCount > 0 {
            return Err(raw::CKR_ARGUMENTS_BAD);
        }

        if !HSM.object_exists(session_id, hObject.into()).ck()? {
            return Err(raw::CKR_OBJECT_HANDLE_INVALID);
        }

        let mut result = Ok(());

        for index in 0..ulCount {
            let attr = unsafe { &mut *pTemplate.add(index as usize) };

            // A few attributes every object nominally carries as an empty
            // value (dates, allowed-mechanism lists we do not restrict).
            if let Some(value) = fixed_empty_attribute(attr.type_) {
                if let Err(rv) = unsafe { write_attribute_value(attr, value) } {
                    result = Err(rv);
                }
                continue;
            }

            let Some(attribute_type) = attribute_type_from_raw(attr.type_) else {
                attr.ulValueLen = raw::CK_UNAVAILABLE_INFORMATION;
                result = Err(raw::CKR_ATTRIBUTE_TYPE_INVALID);
                continue;
            };

            match HSM.object_attribute(session_id, hObject.into(), attribute_type) {
                Ok(Some(attribute)) => {
                    let value = encode_attribute(&attribute);
                    if let Err(rv) = unsafe { write_attribute_value(attr, &value) } {
                        result = Err(rv);
                    }
                }
                Ok(None) => {
                    // The object does not carry this (valid) attribute type.
                    attr.ulValueLen = raw::CK_UNAVAILABLE_INFORMATION;
                    result = Err(raw::CKR_ATTRIBUTE_TYPE_INVALID);
                }
                Err(error) => {
                    attr.ulValueLen = raw::CK_UNAVAILABLE_INFORMATION;
                    result = Err(rv_from(error));
                }
            }
        }

        result
    })
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: raw::CK_FUNCTION_LIST_PTR_PTR) -> raw::CK_RV {
    logging::init();
    debug!("C_GetFunctionList");

    if ppFunctionList.is_null() {
        return raw::CKR_ARGUMENTS_BAD;
    }

    unsafe {
        *ppFunctionList = &FUNCTION_LIST as *const raw::CK_FUNCTION_LIST as raw::CK_FUNCTION_LIST_PTR;
    }

    raw::CKR_OK
}

static FUNCTION_LIST: raw::CK_FUNCTION_LIST = raw::CK_FUNCTION_LIST {
    version: raw::CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: None,
    C_GetMechanismInfo: None,
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: None,
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: None,
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: None,
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

/// Parses a raw `CK_MECHANISM` (including parameter structs) into a typed
/// [`Mechanism`].
///
/// # Safety
///
/// Dereferences `pMechanism` and any parameter pointers inside it.
unsafe fn read_mechanism(pMechanism: raw::CK_MECHANISM_PTR) -> CkResult<Mechanism> {
    if pMechanism.is_null() {
        return Err(raw::CKR_ARGUMENTS_BAD);
    }

    let mechanism = *pMechanism;

    match mechanism.mechanism {
        raw::CKM_GENERIC_SECRET_KEY_GEN => Ok(Mechanism::GenericSecretKeyGen),
        raw::CKM_AES_KEY_GEN => Ok(Mechanism::AesKeyGen),
        raw::CKM_RSA_PKCS_KEY_PAIR_GEN => Ok(Mechanism::RsaPkcsKeyPairGen),
        raw::CKM_EC_KEY_PAIR_GEN => Ok(Mechanism::EcKeyPairGen),
        raw::CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
        raw::CKM_ECDSA => Ok(Mechanism::Ecdsa),
        raw::CKM_SHA256_HMAC => Ok(Mechanism::Sha256Hmac),
        raw::CKM_AES_KEY_WRAP_PAD => Ok(Mechanism::AesKeyWrapPad),
        raw::CKM_AES_GCM => {
            if mechanism.pParameter.is_null() || mechanism.ulParameterLen as usize != size_of::<raw::CK_GCM_PARAMS>() {
                return Err(raw::CKR_MECHANISM_PARAM_INVALID);
            }

            let params = *(mechanism.pParameter as *const raw::CK_GCM_PARAMS);

            // A 96-bit (standard) or 256-bit IV and a 128-bit tag are
            // supported.
            if params.pIv.is_null() || !matches!(params.ulIvLen, 12 | 32) || params.ulTagBits != 128 {
                return Err(raw::CKR_MECHANISM_PARAM_INVALID);
            }

            if params.ulAADLen > MAX_ATTRIBUTE_LENGTH {
                return Err(raw::CKR_MECHANISM_PARAM_INVALID);
            }

            let initialization_vector = slice::from_raw_parts(params.pIv, params.ulIvLen as usize).to_vec();
            let additional_authenticated_data = if params.pAAD.is_null() {
                Vec::new()
            } else {
                slice::from_raw_parts(params.pAAD, params.ulAADLen as usize).to_vec()
            };

            Ok(Mechanism::AesGcm {
                initialization_vector,
                additional_authenticated_data,
            })
        }
        _ => Err(raw::CKR_MECHANISM_INVALID),
    }
}

/// # Safety
///
/// Dereferencing
pub unsafe fn read_attributes(template: raw::CK_ATTRIBUTE_PTR, count: raw::CK_ULONG) -> Vec<Attribute> {
    if template.is_null() {
        return Vec::new();
    }

    unsafe {
        (0..count)
            .map(|index| {
                let attr = *template.add(index as usize);

                if attr.pValue.is_null() {
                    return Attribute::Unknown;
                }

                match attr.type_ {
                    raw::CKA_TOKEN => Attribute::Token(attr_bool(&attr)),
                    raw::CKA_PRIVATE => Attribute::Private(attr_bool(&attr)),
                    raw::CKA_SENSITIVE => Attribute::Sensitive(attr_bool(&attr)),
                    raw::CKA_EXTRACTABLE => Attribute::Extractable(attr_bool(&attr)),
                    raw::CKA_DERIVE => Attribute::Derive(attr_bool(&attr)),
                    raw::CKA_SIGN => Attribute::Sign(attr_bool(&attr)),
                    raw::CKA_VERIFY => Attribute::Verify(attr_bool(&attr)),
                    raw::CKA_ENCRYPT => Attribute::Encrypt(attr_bool(&attr)),
                    raw::CKA_DECRYPT => Attribute::Decrypt(attr_bool(&attr)),
                    raw::CKA_WRAP => Attribute::Wrap(attr_bool(&attr)),
                    raw::CKA_UNWRAP => Attribute::Unwrap(attr_bool(&attr)),

                    raw::CKA_MODULUS_BITS => Attribute::ModulusBits(attr_ulong(&attr)),
                    raw::CKA_VALUE_LEN => Attribute::ValueLen(attr_ulong(&attr)),

                    raw::CKA_EC_PARAMS => attr_bytes(&attr).map_or(Attribute::Unknown, Attribute::EcParams),
                    raw::CKA_EC_POINT => attr_bytes(&attr).map_or(Attribute::Unknown, Attribute::EcPoint),
                    raw::CKA_ID => attr_bytes(&attr).map_or(Attribute::Unknown, Attribute::Id),
                    raw::CKA_VALUE => attr_bytes(&attr).map_or(Attribute::Unknown, Attribute::Value),
                    raw::CKA_MODULUS => attr_bytes(&attr).map_or(Attribute::Unknown, Attribute::Modulus),
                    raw::CKA_PUBLIC_EXPONENT => attr_bytes(&attr).map_or(Attribute::Unknown, Attribute::PublicExponent),

                    raw::CKA_LABEL => attr_bytes(&attr)
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .map_or(Attribute::Unknown, Attribute::Label),

                    raw::CKA_CLASS => {
                        let class = match attr_ulong(&attr) {
                            raw::CKO_PUBLIC_KEY => ObjectClass::PublicKey,
                            raw::CKO_PRIVATE_KEY => ObjectClass::PrivateKey,
                            raw::CKO_SECRET_KEY => ObjectClass::SecretKey,
                            _ => ObjectClass::Unknown,
                        };
                        Attribute::Class(class)
                    }
                    raw::CKA_KEY_TYPE => {
                        let key_type = match attr_ulong(&attr) {
                            raw::CKK_RSA => KeyType::Rsa,
                            raw::CKK_EC => KeyType::Ec,
                            raw::CKK_AES => KeyType::Aes,
                            raw::CKK_GENERIC_SECRET => KeyType::GenericSecret,
                            _ => KeyType::Unknown,
                        };
                        Attribute::KeyType(key_type)
                    }
                    _ => {
                        debug!("unknown attribute: {}", attr.type_);
                        Attribute::Unknown
                    }
                }
            })
            .collect::<Vec<_>>()
    }
}

/// Reads a `CK_BBOOL` attribute value. The caller must have checked
/// `pValue` is non-null.
///
/// # Safety
///
/// Dereferences `attr.pValue`.
unsafe fn attr_bool(attr: &raw::CK_ATTRIBUTE) -> bool {
    unsafe { *(attr.pValue as *const raw::CK_BBOOL) == raw::CK_TRUE }
}

/// Reads a `CK_ULONG` attribute value. The caller must have checked
/// `pValue` is non-null.
///
/// # Safety
///
/// Dereferences `attr.pValue`.
unsafe fn attr_ulong(attr: &raw::CK_ATTRIBUTE) -> raw::CK_ULONG {
    unsafe { *(attr.pValue as *const raw::CK_ULONG) }
}

/// Copies a byte-array attribute value, rejecting over-long ones. The caller
/// must have checked `pValue` is non-null.
///
/// # Safety
///
/// Dereferences `attr.pValue` for `attr.ulValueLen` bytes.
unsafe fn attr_bytes(attr: &raw::CK_ATTRIBUTE) -> Option<Vec<u8>> {
    if attr.ulValueLen > MAX_ATTRIBUTE_LENGTH {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(attr.pValue as raw::CK_BYTE_PTR, attr.ulValueLen as usize) }.to_vec())
}

/// Maps a raw `CKA_*` type onto the domain [`AttributeType`] the object store
/// can serve, or `None` for attributes rustssm does not track.
fn attribute_type_from_raw(type_: raw::CK_ATTRIBUTE_TYPE) -> Option<AttributeType> {
    Some(match type_ {
        raw::CKA_CLASS => AttributeType::Class,
        raw::CKA_KEY_TYPE => AttributeType::KeyType,
        raw::CKA_TOKEN => AttributeType::Token,
        raw::CKA_PRIVATE => AttributeType::Private,
        raw::CKA_SENSITIVE => AttributeType::Sensitive,
        raw::CKA_EXTRACTABLE => AttributeType::Extractable,
        raw::CKA_DERIVE => AttributeType::Derive,
        raw::CKA_SIGN => AttributeType::Sign,
        raw::CKA_VERIFY => AttributeType::Verify,
        raw::CKA_ENCRYPT => AttributeType::Encrypt,
        raw::CKA_DECRYPT => AttributeType::Decrypt,
        raw::CKA_WRAP => AttributeType::Wrap,
        raw::CKA_UNWRAP => AttributeType::Unwrap,
        raw::CKA_LABEL => AttributeType::Label,
        raw::CKA_ID => AttributeType::Id,
        raw::CKA_VALUE => AttributeType::Value,
        raw::CKA_VALUE_LEN => AttributeType::ValueLen,
        raw::CKA_MODULUS => AttributeType::Modulus,
        raw::CKA_MODULUS_BITS => AttributeType::ModulusBits,
        raw::CKA_PUBLIC_EXPONENT => AttributeType::PublicExponent,
        raw::CKA_EC_PARAMS => AttributeType::EcParams,
        raw::CKA_EC_POINT => AttributeType::EcPoint,
        _ => return None,
    })
}

/// Attributes that every object reports as present but empty. Clients (and the
/// rust-cryptoki suite) expect these to be available rather than absent, even
/// though rustssm imposes no dates and no allowed-mechanism restrictions.
fn fixed_empty_attribute(type_: raw::CK_ATTRIBUTE_TYPE) -> Option<&'static [u8]> {
    match type_ {
        raw::CKA_START_DATE | raw::CKA_END_DATE | raw::CKA_ALLOWED_MECHANISMS => Some(&[]),
        _ => None,
    }
}

/// Encodes a typed [`Attribute`] into the raw PKCS#11 byte representation of
/// its value.
fn encode_attribute(attribute: &Attribute) -> Vec<u8> {
    match attribute {
        Attribute::Class(class) => encode_class(*class).to_le_bytes().to_vec(),
        Attribute::KeyType(key_type) => encode_key_type(*key_type).to_le_bytes().to_vec(),

        Attribute::Token(value)
        | Attribute::Private(value)
        | Attribute::Sensitive(value)
        | Attribute::Extractable(value)
        | Attribute::Derive(value)
        | Attribute::Sign(value)
        | Attribute::Verify(value)
        | Attribute::Encrypt(value)
        | Attribute::Decrypt(value)
        | Attribute::Wrap(value)
        | Attribute::Unwrap(value) => vec![if *value { raw::CK_TRUE } else { raw::CK_FALSE }],

        Attribute::ValueLen(value) | Attribute::ModulusBits(value) => (*value as raw::CK_ULONG).to_le_bytes().to_vec(),

        Attribute::Label(value) => value.clone().into_bytes(),
        Attribute::Id(value)
        | Attribute::Value(value)
        | Attribute::Modulus(value)
        | Attribute::PublicExponent(value)
        | Attribute::EcParams(value)
        | Attribute::EcPoint(value) => value.clone(),

        Attribute::Unknown => Vec::new(),
    }
}

fn encode_class(class: ObjectClass) -> raw::CK_ULONG {
    match class {
        ObjectClass::PublicKey => raw::CKO_PUBLIC_KEY,
        ObjectClass::PrivateKey => raw::CKO_PRIVATE_KEY,
        ObjectClass::SecretKey => raw::CKO_SECRET_KEY,
        ObjectClass::Unknown => raw::CKO_VENDOR_DEFINED,
    }
}

fn encode_key_type(key_type: KeyType) -> raw::CK_ULONG {
    match key_type {
        KeyType::Rsa => raw::CKK_RSA,
        KeyType::Ec => raw::CKK_EC,
        KeyType::Aes => raw::CKK_AES,
        KeyType::GenericSecret => raw::CKK_GENERIC_SECRET,
        KeyType::Unknown => raw::CKK_VENDOR_DEFINED,
    }
}

/// Writes an attribute value into a caller-supplied `CK_ATTRIBUTE`, honoring
/// the length-query / buffer-too-small conventions.
///
/// # Safety
///
/// Writes through `attr.pValue` when it is non-null.
unsafe fn write_attribute_value(attr: &mut raw::CK_ATTRIBUTE, value: &[u8]) -> CkResult {
    if attr.pValue.is_null() {
        attr.ulValueLen = value.len() as raw::CK_ULONG;
        Ok(())
    } else if (attr.ulValueLen as usize) < value.len() {
        attr.ulValueLen = value.len() as raw::CK_ULONG;
        Err(raw::CKR_BUFFER_TOO_SMALL)
    } else {
        unsafe {
            ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as raw::CK_BYTE_PTR, value.len());
        }
        attr.ulValueLen = value.len() as raw::CK_ULONG;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_output_null_buffer_requests_length() {
        let data = [1u8, 2, 3, 4];
        let mut len: raw::CK_ULONG = 0;

        let result = unsafe { write_output(&data, ptr::null_mut(), &mut len) };

        assert!(result.is_ok());
        assert_eq!(len, 4);
    }

    #[test]
    fn write_output_small_buffer_reports_required_length() {
        let data = [1u8, 2, 3, 4];
        let mut buffer = [0u8; 2];
        let mut len: raw::CK_ULONG = buffer.len() as raw::CK_ULONG;

        let result = unsafe { write_output(&data, buffer.as_mut_ptr(), &mut len) };

        assert_eq!(result, Err(raw::CKR_BUFFER_TOO_SMALL));
        assert_eq!(len, 4);
    }

    #[test]
    fn write_output_copies_and_reports_actual_length() {
        let data = [1u8, 2, 3, 4];
        let mut buffer = [0u8; 8];
        let mut len: raw::CK_ULONG = buffer.len() as raw::CK_ULONG;

        let result = unsafe { write_output(&data, buffer.as_mut_ptr(), &mut len) };

        assert!(result.is_ok());
        assert_eq!(len, 4);
        assert_eq!(&buffer[..4], &data);
    }

    #[test]
    fn write_output_null_length_pointer_is_rejected() {
        let data = [1u8];
        let mut buffer = [0u8; 1];

        let result = unsafe { write_output(&data, buffer.as_mut_ptr(), ptr::null_mut()) };

        assert_eq!(result, Err(raw::CKR_ARGUMENTS_BAD));
    }
}
