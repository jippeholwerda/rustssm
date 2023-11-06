#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{ffi::CStr, ptr};

use once_cell::sync::Lazy;
use p256::ecdsa;
use rand::rngs::OsRng;
use rsa::{pkcs1v15::SigningKey, sha2::Sha256, signature::Keypair, RsaPrivateKey};

use crate::{
    hsm::Hsm,
    operation::Operation,
    pin::Pin,
    signing::{Sign, SignatureLength, Verify},
};

mod hsm;
mod keys;
mod operation;
mod pin;
mod raw;
mod session;
mod signing;
mod slot;

static HSM: Lazy<Hsm> = Lazy::new(Hsm::default);

#[no_mangle]
pub extern "C" fn C_Initialize(_pInitArgs: raw::CK_VOID_PTR) -> raw::CK_RV {
    println!("C_Initialize");
    raw::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Finalize(_pReserved: raw::CK_VOID_PTR) -> raw::CK_RV {
    println!("C_Finalize");
    raw::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetInfo(_pInfo: raw::CK_INFO_PTR) -> raw::CK_RV {
    println!("C_GetInfo");
    raw::CKR_OK
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
    println!("C_GetSlotList");

    if pSlotList.is_null() {
        unsafe {
            *pulCount = HSM.slots.read().unwrap().len().try_into().unwrap();
        }
    } else {
        unsafe {
            *pSlotList = 1;
        }
    }

    raw::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// todo
pub unsafe extern "C" fn C_InitToken(
    slotID: raw::CK_SLOT_ID,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
    pLabel: raw::CK_UTF8CHAR_PTR,
) -> raw::CK_RV {
    let pin = unsafe { Pin::from_raw_parts(pPin, ulPinLen) };
    let label = unsafe { CStr::from_ptr(pLabel.cast::<i8>()).to_str().ok().map(String::from) };

    let slot = &mut HSM.slots.write().unwrap()[slotID as usize - 1];
    slot.initialized = true;
    slot.so_pin = pin;
    slot.label = label;

    raw::CKR_OK
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
    println!("C_OpenSession");

    let slot = &HSM.slots.write().unwrap()[slotID as usize - 1];

    if (flags & raw::CKF_SERIAL_SESSION) == 0 {
        return raw::CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    if (flags & raw::CKF_RW_SESSION) == 0 && HSM.is_so_write_session_open() {
        return raw::CKR_SESSION_READ_WRITE_SO_EXISTS;
    };

    // if (flags & raw::CKF_RW_SESSION) == raw::CKF_RW_SESSION {
    let session_id = slot.create_session(&HSM, slot.id.clone());
    unsafe {
        *phSession = session_id.0;
    }

    raw::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(hSession: raw::CK_SESSION_HANDLE) -> raw::CK_RV {
    println!("C_CloseSession");
    println!("C_CloseSession session: {}", hSession);

    let mut sessions = HSM.sessions.write().unwrap();
    sessions.remove(hSession.try_into().unwrap());

    raw::CKR_OK
}

#[no_mangle]
/// # Safety
/// todo
pub unsafe extern "C" fn C_Login(
    hSession: raw::CK_SESSION_HANDLE,
    userType: raw::CK_USER_TYPE,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
) -> raw::CK_RV {
    println!("C_Login");
    println!("C_Login session: {}", hSession);

    let pin = unsafe { Pin::from_raw_parts(pPin, ulPinLen) };
    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();
    let slots = HSM.slots.read().unwrap();
    let slot = slots.get(session.slot_id.0.into()).unwrap();

    match userType {
        raw::CKU_SO => {
            if slot
                .so_pin
                .as_ref()
                .is_some_and(|stored_pin| pin.is_some_and(|pin| *stored_pin == pin))
            {
                session.so_authenticated = true;
                return raw::CKR_OK;
            }
        }
        raw::CKU_USER => {
            if slot
                .user_pin
                .as_ref()
                .is_some_and(|stored_pin| pin.is_some_and(|pin| *stored_pin == pin))
            {
                session.user_authenticated = true;
                return raw::CKR_OK;
            }
        }
        _ => return raw::CKR_USER_TYPE_INVALID,
    }

    raw::CKR_PIN_INCORRECT
}

#[no_mangle]
/// # Safety
/// todo
pub unsafe extern "C" fn C_LoginUser(
    hSession: raw::CK_SESSION_HANDLE,
    userType: raw::CK_USER_TYPE,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
    _pUsername: raw::CK_UTF8CHAR_PTR,
    _ulUsernameLen: raw::CK_ULONG,
) -> raw::CK_RV {
    println!("C_LoginUser");

    C_Login(hSession, userType, pPin, ulPinLen)
}

#[no_mangle]
pub extern "C" fn C_Logout(hSession: raw::CK_SESSION_HANDLE) -> raw::CK_RV {
    println!("C_Logout");
    println!("C_Logout session: {}", hSession);

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    session.so_authenticated = false;
    session.user_authenticated = false;

    raw::CKR_OK
}

#[no_mangle]
/// # Safety
/// todo
pub unsafe extern "C" fn C_InitPIN(
    hSession: raw::CK_SESSION_HANDLE,
    pPin: raw::CK_UTF8CHAR_PTR,
    ulPinLen: raw::CK_ULONG,
) -> raw::CK_RV {
    println!("C_InitPIN");

    let pin = unsafe { Pin::from_raw_parts(pPin, ulPinLen) };
    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();
    let mut slots = HSM.slots.write().unwrap();
    let slot = slots.get_mut(session.slot_id.0.into()).unwrap();

    if !slot.initialized {
        return raw::CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if !session.so_authenticated {
        return raw::CKR_USER_NOT_LOGGED_IN;
    }

    slot.user_pin = pin;

    raw::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// Dereferencing
pub unsafe extern "C" fn C_GenerateKeyPair(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    _pPublicKeyTemplate: raw::CK_ATTRIBUTE_PTR,
    _ulPublicKeyAttributeCount: raw::CK_ULONG,
    _pPrivateKeyTemplate: raw::CK_ATTRIBUTE_PTR,
    _ulPrivateKeyAttributeCount: raw::CK_ULONG,
    phPublicKey: raw::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: raw::CK_OBJECT_HANDLE_PTR,
) -> raw::CK_RV {
    println!("C_GenerateKeyPair");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    println!("C_GenerateKeyPair: {}", (*pMechanism).mechanism);

    let mechanism = unsafe { (*pMechanism).mechanism };

    match mechanism {
        raw::CKM_RSA_PKCS_KEY_PAIR_GEN => {
            let mut rng = rand::thread_rng();
            let bits = 1024;
            // let private_key = RsaPrivateKey::new_with_exp(&mut rng, bits, &BigUint::from_bytes_le(&[1, 0, 1]))
            //     .expect("failed to generate a key");
            let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

            let mut objects = session.objects.write().unwrap();
            let priv_object_id = objects.insert(postcard::to_allocvec(&private_key).unwrap());
            let pub_object_id = objects.insert(postcard::to_allocvec(&private_key).unwrap());

            *phPublicKey = pub_object_id as u64;
            *phPrivateKey = priv_object_id as u64;
        }
        raw::CKM_EC_KEY_PAIR_GEN => {
            let signing_key = ecdsa::SigningKey::random(&mut OsRng);
            let bytes = signing_key.to_bytes().to_vec();
            let verifying_key = *signing_key.verifying_key();

            let mut objects = session.objects.write().unwrap();
            let priv_object_id = objects.insert(bytes);
            let pub_object_id = objects.insert(postcard::to_allocvec(&verifying_key).unwrap());

            *phPublicKey = pub_object_id as u64;
            *phPrivateKey = priv_object_id as u64;
        }
        _ => return raw::CKR_MECHANISM_INVALID,
    };

    raw::CKR_OK
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
    println!("C_SignInit");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_some() {
        return raw::CKR_OPERATION_ACTIVE;
    }

    let mechanism = unsafe { (*pMechanism).mechanism };

    match mechanism {
        raw::CKM_RSA_PKCS => {
            let private_key: RsaPrivateKey =
                postcard::from_bytes(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap()).unwrap();

            let signing_key = Box::new(SigningKey::<Sha256>::new(private_key));

            session.operation.set(Operation::SignRsa { signing_key }).unwrap();
        }
        raw::CKM_ECDSA => {
            let signing_key = Box::new(
                ecdsa::SigningKey::from_slice(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap())
                    .unwrap(),
            );
            session.operation.set(Operation::SignEcdsa { signing_key }).unwrap();
        }
        _ => return raw::CKR_MECHANISM_INVALID,
    }

    raw::CKR_OK
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
    println!("C_Sign");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_none() {
        return raw::CKR_OPERATION_NOT_INITIALIZED;
    }

    unsafe {
        let data = std::slice::from_raw_parts(pData, ulDataLen.try_into().unwrap());

        if pSignature.is_null() {
            let operation = session.operation.get().unwrap();
            *pulSignatureLen = operation.signature_length();
        } else {
            let operation = session.operation.take().unwrap();
            let signature = operation.sign(data);

            std::ptr::copy_nonoverlapping(signature.0.as_ptr(), pSignature, signature.0.len());
            *pulSignatureLen = signature.0.len().try_into().unwrap();
        }
    }

    raw::CKR_OK
}

/// # Safety
///
/// Dereferencing
#[no_mangle]
pub unsafe extern "C" fn C_VerifyInit(
    hSession: raw::CK_SESSION_HANDLE,
    pMechanism: raw::CK_MECHANISM_PTR,
    hKey: raw::CK_OBJECT_HANDLE,
) -> raw::CK_RV {
    println!("C_VerifyInit");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_some() {
        return raw::CKR_OPERATION_ACTIVE;
    }

    unsafe {
        match (*pMechanism).mechanism {
            raw::CKM_RSA_PKCS => {
                let private_key: RsaPrivateKey =
                    postcard::from_bytes(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap())
                        .unwrap();
                let signing_key = SigningKey::<Sha256>::new(private_key);
                let verifying_key = Box::new(signing_key.verifying_key());

                session.operation.set(Operation::VerifyRsa { verifying_key }).unwrap();
            }
            raw::CKM_ECDSA => {
                let verifying_key: Box<ecdsa::VerifyingKey> = Box::new(
                    postcard::from_bytes(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap())
                        .unwrap(),
                );
                session.operation.set(Operation::VerifyEcdsa { verifying_key }).unwrap();
            }
            _ => return raw::CKR_MECHANISM_INVALID,
        }
    }

    raw::CKR_OK
}

/// # Safety
///
/// Dereferencing
#[no_mangle]
pub unsafe extern "C" fn C_Verify(
    hSession: raw::CK_SESSION_HANDLE,
    pData: raw::CK_BYTE_PTR,
    ulDataLen: raw::CK_ULONG,
    pSignature: raw::CK_BYTE_PTR,
    ulSignatureLen: raw::CK_ULONG,
) -> raw::CK_RV {
    println!("C_Verify");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_none() {
        return raw::CKR_OPERATION_NOT_INITIALIZED;
    }

    let operation = session.operation.take().unwrap();
    let data = std::slice::from_raw_parts(pData, ulDataLen.try_into().unwrap());
    println!("{:?}", data);
    let signature = std::slice::from_raw_parts(pSignature, ulSignatureLen.try_into().unwrap());

    println!("C_Verify sig: {:?}", signature);
    println!("C_Verify length: {}", ulSignatureLen);

    if !operation.verify(data, signature) {
        return raw::CKR_SIGNATURE_INVALID;
    }

    raw::CKR_OK
}

pub extern "C" fn C_DestroyObject(hSession: raw::CK_SESSION_HANDLE, hObject: raw::CK_OBJECT_HANDLE) -> raw::CK_RV {
    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    session.objects.write().unwrap().remove(hObject.try_into().unwrap());

    raw::CKR_OK
}

/// # Safety
///
/// Dereferencing
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: raw::CK_FUNCTION_LIST_PTR_PTR) -> raw::CK_RV {
    unsafe {
        let mut flist = raw::CK_FUNCTION_LIST {
            version: raw::CK_VERSION {
                major: 0x03,
                minor: 0x00,
            },
            C_Initialize: Some(C_Initialize),
            C_Finalize: Some(C_Finalize),
            C_GetInfo: Some(C_GetInfo),
            C_GetFunctionList: Some(C_GetFunctionList),
            C_GetSlotList: Some(C_GetSlotList),
            C_GetSlotInfo: Option::None,
            C_GetTokenInfo: None,
            C_GetMechanismList: None,
            C_GetMechanismInfo: None,
            C_InitToken: Some(C_InitToken),
            C_InitPIN: Some(C_InitPIN),
            C_SetPIN: None,
            C_OpenSession: Some(C_OpenSession),
            C_CloseSession: Some(C_CloseSession),
            C_CloseAllSessions: None,
            C_GetSessionInfo: None,
            C_GetOperationState: None,
            C_SetOperationState: None,
            C_Login: Some(C_Login),
            C_Logout: Some(C_Logout),
            // C_LoginUser: Some(C_LoginUser),
            C_CreateObject: None,
            C_CopyObject: None,
            C_DestroyObject: Some(C_DestroyObject),
            C_GetObjectSize: None,
            C_GetAttributeValue: None,
            C_SetAttributeValue: None,
            C_FindObjectsInit: None,
            C_FindObjects: None,
            C_FindObjectsFinal: None,
            C_EncryptInit: None,
            C_Encrypt: None,
            C_EncryptUpdate: None,
            C_EncryptFinal: None,
            C_DecryptInit: None,
            C_Decrypt: None,
            C_DecryptUpdate: None,
            C_DecryptFinal: None,
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
            C_GenerateKey: None,
            C_GenerateKeyPair: Some(C_GenerateKeyPair),
            C_WrapKey: None,
            C_UnwrapKey: None,
            C_DeriveKey: None,
            C_SeedRandom: None,
            C_GenerateRandom: None,
            C_GetFunctionStatus: None,
            C_CancelFunction: None,
            C_WaitForSlotEvent: None,
            // C_DecryptMessage: None,
            // C_DecryptMessageBegin: None,
            // C_DecryptMessageNext: None,
            // C_EncryptMessage: None,
            // C_EncryptMessageBegin: None,
            // C_EncryptMessageNext: None,
            // C_GetInterface: None,
            // C_GetInterfaceList: None,
            // C_MessageDecryptInit: None,
            // C_MessageDecryptFinal: None,
            // C_MessageEncryptInit: None,
            // C_MessageEncryptFinal: None,
            // C_MessageSignInit: None,
            // C_MessageSignFinal: None,
            // C_MessageVerifyInit: None,
            // C_MessageVerifyFinal: None,
            // C_SessionCancel: None,
            // C_SignMessageBegin: None,
            // C_SignMessage: None,
            // C_SignMessageNext: None,
            // C_VerifyMessage: None,
            // C_VerifyMessageBegin: None,
            // C_VerifyMessageNext: None,
        };

        let function_list = ptr::addr_of_mut!(flist);
        *ppFunctionList = function_list;
    };

    raw::CKR_OK
}

#[cfg(test)]
mod tests {
    use crate::signing::Signature;
    use rsa::{
        pkcs1v15,
        pkcs1v15::SigningKey,
        sha2::Sha256,
        signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier},
        RsaPrivateKey,
    };

    #[test]
    fn verify_sign_rsa() {
        let mut rng = rand::thread_rng();
        let bits = 1024;

        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = signing_key.verifying_key();

        let data = [0xFF, 0x55, 0xDD];

        let mut rng = rand::thread_rng();
        let signature = signing_key.sign_with_rng(&mut rng, &data);
        let wrapped_signature = Signature(signature.to_bytes().to_vec());

        let pSignature = wrapped_signature.0.as_ptr().cast_mut();
        let ulSignatureLen = wrapped_signature.0.len();

        unsafe {
            let data = std::slice::from_raw_parts(data.as_ptr(), data.len());
            let signature = std::slice::from_raw_parts(pSignature, ulSignatureLen);

            let signature = pkcs1v15::Signature::try_from(signature).unwrap();

            verifying_key.verify(data, &signature).unwrap();
        }
    }
}
