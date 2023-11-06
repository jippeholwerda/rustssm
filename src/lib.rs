#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{
    ffi::CStr,
    ptr, slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock, RwLock,
    },
};

use once_cell::sync::Lazy;
use p256::{ecdsa, ecdsa::signature::Signer};
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15,
    pkcs1v15::{SigningKey, VerifyingKey},
    sha2::Sha256,
    signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier},
    RsaPrivateKey,
};
use slab::Slab;

mod pkcs11 {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

static HSM: Lazy<Hsm> = Lazy::new(Hsm::default);

pub struct Hsm {
    is_so_write_session_open: AtomicBool,
    pub slots: RwLock<Slab<Slot>>,
    pub sessions: RwLock<Slab<Session>>,
}

impl Default for Hsm {
    fn default() -> Self {
        Self {
            is_so_write_session_open: AtomicBool::new(false),
            slots: RwLock::new(Slab::from_iter((0..4).map(|i| (i.into(), Slot::new(i))))),
            sessions: RwLock::new(Slab::default()),
        }
    }
}

impl Hsm {
    fn is_so_write_session_open(&self) -> bool {
        self.is_so_write_session_open.load(Ordering::Acquire)
    }

    fn open_so_write_session(&self) {
        self.is_so_write_session_open.store(true, Ordering::Release)
    }

    fn close_so_write_session(&self) {
        self.is_so_write_session_open.store(false, Ordering::Release)
    }
}

// todo: securely store the pin
#[derive(Eq, PartialEq)]
pub struct Pin(String);

impl Pin {
    fn from_raw_parts(pPin: pkcs11::CK_UTF8CHAR_PTR, ulPinLen: pkcs11::CK_ULONG) -> Option<Self> {
        unsafe {
            String::from_utf8(slice::from_raw_parts(pPin, ulPinLen as usize).into())
                .ok()
                .map(Self)
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SlotId(u8);

pub struct Slot {
    pub id: SlotId,
    pub initialized: bool,
    pub so_pin: Option<Pin>,
    pub user_pin: Option<Pin>,
    pub label: Option<String>,
}

impl Slot {
    fn new(id: u8) -> Self {
        Self {
            id: SlotId(id),
            initialized: false,
            so_pin: None,
            user_pin: None,
            label: None,
        }
    }

    fn create_session(&self, token: &Hsm, slot: SlotId) -> SessionId {
        let index = token.sessions.write().unwrap().insert(Session::new(slot));
        SessionId(index as u64)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

// todo: have different kinds of sessions (R/W SO, R/W Public, R/W User, R/O SO, R/O User as enum values)
pub struct Session {
    pub slot_id: SlotId,
    pub so_authenticated: bool,
    pub user_authenticated: bool,
    pub objects: RwLock<Slab<Vec<u8>>>,
    pub operation: OnceLock<Operation>,
}

impl Session {
    fn new(slot_id: SlotId) -> Self {
        Self {
            slot_id,
            so_authenticated: false,
            user_authenticated: false,
            objects: RwLock::new(Slab::default()),
            operation: OnceLock::new(),
        }
    }
}

#[derive(Debug)]
pub struct PrivateKey(pkcs11::CK_OBJECT_HANDLE);

pub struct Signature(Vec<u8>);

#[derive(Debug)]
pub enum Operation {
    SignRsa { signing_key: Box<SigningKey<Sha256>> },
    VerifyRsa { verifying_key: Box<VerifyingKey<Sha256>> },
    SignEcdsa { signing_key: Box<ecdsa::SigningKey> },
    VerifyEcdsa { verifying_key: Box<ecdsa::VerifyingKey> },
}

trait Sign {
    fn sign(self, data: &[u8]) -> Signature;
}

trait SignatureLength {
    fn signature_length(&self) -> u64;
}

trait Verify {
    fn verify(self, data: &[u8], signature: &[u8]) -> bool;
}

impl Sign for Operation {
    fn sign(self, data: &[u8]) -> Signature {
        match self {
            Operation::SignRsa { signing_key } => {
                let mut rng = rand::thread_rng();
                let signature = signing_key.sign_with_rng(&mut rng, data);
                Signature(signature.to_bytes().to_vec())
            }
            Operation::SignEcdsa { signing_key } => {
                let signature: ecdsa::Signature = signing_key.sign(data);
                Signature(signature.to_bytes().to_vec())
            }
            _ => panic!("operation not supported"),
        }
    }
}

impl SignatureLength for Operation {
    fn signature_length(&self) -> u64 {
        match self {
            Operation::SignRsa { .. } => 128, // todo: determine from key
            Operation::SignEcdsa { .. } => 64,
            _ => panic!("operation not supported"),
        }
    }
}

impl Verify for Operation {
    fn verify(self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            Operation::VerifyRsa { verifying_key } => {
                let signature = pkcs1v15::Signature::try_from(signature).unwrap();
                let result = verifying_key.verify(data, &signature);
                result.is_ok()
            }
            Operation::VerifyEcdsa { verifying_key } => {
                let signature = ecdsa::Signature::from_slice(signature).unwrap();
                let result = verifying_key.verify(data, &signature);
                result.is_ok()
            }
            _ => panic!("operation not supported"),
        }
    }
}

#[no_mangle]
pub extern "C" fn C_Initialize(_pInitArgs: pkcs11::CK_VOID_PTR) -> pkcs11::CK_RV {
    println!("C_Initialize");
    pkcs11::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Finalize(_pReserved: pkcs11::CK_VOID_PTR) -> pkcs11::CK_RV {
    println!("C_Finalize");
    pkcs11::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetInfo(_pInfo: pkcs11::CK_INFO_PTR) -> pkcs11::CK_RV {
    println!("C_GetInfo");
    pkcs11::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// Deferencing
pub unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: pkcs11::CK_BBOOL,
    pSlotList: pkcs11::CK_SLOT_ID_PTR,
    pulCount: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    println!("C_GetSlotList");

    if pSlotList.is_null() {
        unsafe {
            println!("C_GetSlotList is null: {}", *pulCount);
            *pulCount = HSM.slots.read().unwrap().len().try_into().unwrap();
        }
    } else {
        unsafe {
            println!("C_GetSlotList {}", *pulCount);
            *pSlotList = 1;
        }
    }

    pkcs11::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_InitToken(
    slotID: pkcs11::CK_SLOT_ID,
    pPin: pkcs11::CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11::CK_ULONG,
    pLabel: pkcs11::CK_UTF8CHAR_PTR,
) -> pkcs11::CK_RV {
    let pin = Pin::from_raw_parts(pPin, ulPinLen);
    let label = unsafe { CStr::from_ptr(pLabel.cast::<i8>()).to_str().ok().map(String::from) };

    let slot = &mut HSM.slots.write().unwrap()[slotID as usize - 1];
    slot.initialized = true;
    slot.so_pin = pin;
    slot.label = label;

    pkcs11::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// Deferencing
pub unsafe extern "C" fn C_OpenSession(
    slotID: pkcs11::CK_SLOT_ID,
    flags: pkcs11::CK_FLAGS,
    _pApplication: pkcs11::CK_VOID_PTR,
    _Notify: pkcs11::CK_NOTIFY,
    phSession: pkcs11::CK_SESSION_HANDLE_PTR,
) -> pkcs11::CK_RV {
    println!("C_OpenSession");

    let slot = &HSM.slots.write().unwrap()[slotID as usize - 1];

    if (flags & pkcs11::CKF_SERIAL_SESSION) == 0 {
        return pkcs11::CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    if (flags & pkcs11::CKF_RW_SESSION) == 0 && HSM.is_so_write_session_open() {
        return pkcs11::CKR_SESSION_READ_WRITE_SO_EXISTS;
    };

    // if (flags & pkcs11::CKF_RW_SESSION) == pkcs11::CKF_RW_SESSION {
    let session_id = slot.create_session(&HSM, slot.id.clone());
    unsafe {
        *phSession = session_id.0;
    }

    pkcs11::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    println!("C_CloseSession");
    println!("C_CloseSession session: {}", hSession);

    let mut sessions = HSM.sessions.write().unwrap();
    sessions.remove(hSession.try_into().unwrap());

    pkcs11::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Login(
    hSession: pkcs11::CK_SESSION_HANDLE,
    userType: pkcs11::CK_USER_TYPE,
    pPin: pkcs11::CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    println!("C_Login");
    println!("C_Login session: {}", hSession);

    let pin = Pin::from_raw_parts(pPin, ulPinLen);
    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();
    let slots = HSM.slots.read().unwrap();
    let slot = slots.get(session.slot_id.0.into()).unwrap();

    match userType {
        pkcs11::CKU_SO => {
            if slot
                .so_pin
                .as_ref()
                .is_some_and(|stored_pin| pin.is_some_and(|pin| *stored_pin == pin))
            {
                session.so_authenticated = true;
                return pkcs11::CKR_OK;
            }
        }
        pkcs11::CKU_USER => {
            if slot
                .user_pin
                .as_ref()
                .is_some_and(|stored_pin| pin.is_some_and(|pin| *stored_pin == pin))
            {
                session.user_authenticated = true;
                return pkcs11::CKR_OK;
            }
        }
        _ => return pkcs11::CKR_USER_TYPE_INVALID,
    }

    pkcs11::CKR_PIN_INCORRECT
}

#[no_mangle]
pub extern "C" fn C_LoginUser(
    hSession: pkcs11::CK_SESSION_HANDLE,
    userType: pkcs11::CK_USER_TYPE,
    pPin: pkcs11::CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11::CK_ULONG,
    _pUsername: pkcs11::CK_UTF8CHAR_PTR,
    _ulUsernameLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    println!("C_LoginUser");

    C_Login(hSession, userType, pPin, ulPinLen)
}

#[no_mangle]
pub extern "C" fn C_Logout(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    println!("C_Logout");
    println!("C_Logout session: {}", hSession);

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    session.so_authenticated = false;
    session.user_authenticated = false;

    pkcs11::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_InitPIN(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPin: pkcs11::CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    println!("C_InitPIN");

    let pin = Pin::from_raw_parts(pPin, ulPinLen);
    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();
    let mut slots = HSM.slots.write().unwrap();
    let slot = slots.get_mut(session.slot_id.0.into()).unwrap();

    if !slot.initialized {
        return pkcs11::CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if !session.so_authenticated {
        return pkcs11::CKR_USER_NOT_LOGGED_IN;
    }

    slot.user_pin = pin;

    pkcs11::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// Deferencing
pub unsafe extern "C" fn C_GenerateKeyPair(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    _pPublicKeyTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    _ulPublicKeyAttributeCount: pkcs11::CK_ULONG,
    _pPrivateKeyTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    _ulPrivateKeyAttributeCount: pkcs11::CK_ULONG,
    phPublicKey: pkcs11::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: pkcs11::CK_OBJECT_HANDLE_PTR,
) -> pkcs11::CK_RV {
    println!("C_GenerateKeyPair");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    println!("C_GenerateKeyPair: {}", (*pMechanism).mechanism);

    let mechanism = unsafe { (*pMechanism).mechanism };

    match mechanism {
        pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN => {
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
        pkcs11::CKM_EC_KEY_PAIR_GEN => {
            let signing_key = ecdsa::SigningKey::random(&mut OsRng);
            let bytes = signing_key.to_bytes().to_vec();
            let verifying_key = *signing_key.verifying_key();

            let mut objects = session.objects.write().unwrap();
            let priv_object_id = objects.insert(bytes);
            let pub_object_id = objects.insert(postcard::to_allocvec(&verifying_key).unwrap());

            *phPublicKey = pub_object_id as u64;
            *phPrivateKey = priv_object_id as u64;
        }
        _ => return pkcs11::CKR_MECHANISM_INVALID,
    };

    pkcs11::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// Deferencing
pub unsafe extern "C" fn C_SignInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    println!("C_SignInit");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_some() {
        return pkcs11::CKR_OPERATION_ACTIVE;
    }

    let mechanism = unsafe { (*pMechanism).mechanism };

    match mechanism {
        pkcs11::CKM_RSA_PKCS => {
            let private_key: RsaPrivateKey =
                postcard::from_bytes(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap()).unwrap();

            let signing_key = Box::new(SigningKey::<Sha256>::new(private_key));

            session.operation.set(Operation::SignRsa { signing_key }).unwrap();
        }
        pkcs11::CKM_ECDSA => {
            let signing_key = Box::new(
                ecdsa::SigningKey::from_slice(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap())
                    .unwrap(),
            );
            session.operation.set(Operation::SignEcdsa { signing_key }).unwrap();
        }
        _ => return pkcs11::CKR_MECHANISM_INVALID,
    }

    pkcs11::CKR_OK
}

#[no_mangle]
/// # Safety
///
/// Deferencing
pub unsafe extern "C" fn C_Sign(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: pkcs11::CK_BYTE_PTR,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: pkcs11::CK_BYTE_PTR,
    pulSignatureLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    println!("C_Sign");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_none() {
        return pkcs11::CKR_OPERATION_NOT_INITIALIZED;
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

    pkcs11::CKR_OK
}

/// # Safety
///
/// Deferencing
#[no_mangle]
pub unsafe extern "C" fn C_VerifyInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    println!("C_VerifyInit");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_some() {
        return pkcs11::CKR_OPERATION_ACTIVE;
    }

    unsafe {
        match (*pMechanism).mechanism {
            pkcs11::CKM_RSA_PKCS => {
                let private_key: RsaPrivateKey =
                    postcard::from_bytes(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap())
                        .unwrap();
                let signing_key = SigningKey::<Sha256>::new(private_key);
                let verifying_key = Box::new(signing_key.verifying_key());

                session.operation.set(Operation::VerifyRsa { verifying_key }).unwrap();
            }
            pkcs11::CKM_ECDSA => {
                let verifying_key: Box<ecdsa::VerifyingKey> = Box::new(
                    postcard::from_bytes(session.objects.read().unwrap().get(hKey.try_into().unwrap()).unwrap())
                        .unwrap(),
                );
                session.operation.set(Operation::VerifyEcdsa { verifying_key }).unwrap();
            }
            _ => return pkcs11::CKR_MECHANISM_INVALID,
        }
    }

    pkcs11::CKR_OK
}

/// # Safety
///
/// Deferencing
#[no_mangle]
pub unsafe extern "C" fn C_Verify(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: pkcs11::CK_BYTE_PTR,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: pkcs11::CK_BYTE_PTR,
    ulSignatureLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    println!("C_Verify");

    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    if session.operation.get().is_none() {
        return pkcs11::CKR_OPERATION_NOT_INITIALIZED;
    }

    let operation = session.operation.take().unwrap();
    let data = std::slice::from_raw_parts(pData, ulDataLen.try_into().unwrap());
    println!("{:?}", data);
    let signature = std::slice::from_raw_parts(pSignature, ulSignatureLen.try_into().unwrap());

    println!("C_Verify sig: {:?}", signature);
    println!("C_Verify length: {}", ulSignatureLen);

    if !operation.verify(data, signature) {
        return pkcs11::CKR_SIGNATURE_INVALID;
    }

    pkcs11::CKR_OK
}

pub extern "C" fn C_DestroyObject(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hObject: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    let mut sessions = HSM.sessions.write().unwrap();
    let session = sessions.get_mut(hSession.try_into().unwrap()).unwrap();

    session.objects.write().unwrap().remove(hObject.try_into().unwrap());

    pkcs11::CKR_OK
}

/// # Safety
///
/// Deferencing
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: pkcs11::CK_FUNCTION_LIST_PTR_PTR) -> pkcs11::CK_RV {
    unsafe {
        let mut flist = pkcs11::CK_FUNCTION_LIST {
            version: pkcs11::CK_VERSION {
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

    pkcs11::CKR_OK
}

#[cfg(test)]
mod tests {
    use crate::Signature;
    use rsa::{
        pkcs1v15,
        pkcs1v15::SigningKey,
        sha2::Sha256,
        signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier},
        RsaPrivateKey,
    };

    #[test]
    fn round_trip_compression_decompression() {
        let mut rng = rand::thread_rng();
        let bits = 1024;
        // let private_key = RsaPrivateKey::new_with_exp(&mut rng, bits, &BigUint::from_bytes_le(&[1, 0, 1]))
        //     .expect("failed to generate a key");
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = signing_key.verifying_key();

        let data = [0xFF, 0x55, 0xDD];

        let mut rng = rand::thread_rng();
        let signature = signing_key.sign_with_rng(&mut rng, &data);
        let wrapped_signature = Signature(signature.to_bytes().to_vec());

        println!("C_Sign length: {}", wrapped_signature.0.len());
        let pSignature = wrapped_signature.0.as_ptr().cast_mut();
        let ulSignatureLen = wrapped_signature.0.len();

        unsafe {
            let data = std::slice::from_raw_parts(data.as_ptr(), data.len());
            let signature = std::slice::from_raw_parts(pSignature, ulSignatureLen);

            let signature = pkcs1v15::Signature::try_from(signature).unwrap();

            // let len: u64 = signature.0.len().try_into().unwrap();
            // println!("C_Sign length: {}", len / 8);
            // *pulSignatureLen = len / 8;
            //
            // let signature = pkcs1v15::Signature::try_from(signature).unwrap();
            verifying_key.verify(data, &signature).unwrap();
        }
    }
}
