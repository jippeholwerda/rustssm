use aes::cipher::block_padding::NoPadding;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::BlockModeDecrypt;
use aes::cipher::BlockModeEncrypt;
use aes::cipher::KeyInit;
use aes::cipher::KeyIvInit;
use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::aes::cipher::consts::U32;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use aes_gcm::AesGcm;
use aes_gcm::Nonce;

use crate::operation::Operation;

/// Length in bytes of an AES-GCM authentication tag.
pub const AES_GCM_TAG_LENGTH: usize = 16;

/// AES block length in bytes; `CKM_AES_ECB`/`CKM_AES_CBC` inputs must be a
/// multiple of it.
pub const AES_BLOCK_LENGTH: usize = 16;

/// AES-GCM with a 32-byte initialization vector. AES-GCM's nonce length is a
/// compile-time type parameter, so each supported IV length needs its own
/// concrete cipher type; the default `Aes*Gcm` aliases fix it at 12 bytes.
type Aes128Gcm32 = AesGcm<Aes128, U32>;
type Aes256Gcm32 = AesGcm<Aes256, U32>;

/// Encrypts under a concrete AES-GCM cipher. The nonce length must match the
/// cipher's `NonceSize` (callers dispatch on it), so a mismatch here is a
/// caller bug rather than an input error.
fn gcm_encrypt<C>(key: &[u8], nonce: &[u8], payload: Payload) -> Option<Vec<u8>>
where
    C: KeyInit + Aead,
{
    let cipher = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C::NonceSize>::try_from(nonce).ok()?;
    cipher.encrypt(&nonce, payload).ok()
}

/// Decrypts under a concrete AES-GCM cipher. A `None` result is an
/// authentication-tag mismatch (or a ciphertext shorter than the tag).
fn gcm_decrypt<C>(key: &[u8], nonce: &[u8], payload: Payload) -> Option<Vec<u8>>
where
    C: KeyInit + Aead,
{
    let cipher = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C::NonceSize>::try_from(nonce).ok()?;
    cipher.decrypt(&nonce, payload).ok()
}

/// Runs `$body` with `$C` bound to the AES variant matching the key length.
/// `None` for any other length — the init paths validate 16/24/32, so only a
/// corrupt stored key reaches that.
macro_rules! with_aes {
    ($key:expr, $C:ident => $body:expr) => {
        match $key.len() {
            16 => {
                type $C = Aes128;
                $body
            }
            24 => {
                type $C = Aes192;
                $body
            }
            32 => {
                type $C = Aes256;
                $body
            }
            _ => None,
        }
    };
}

/// `CKM_AES_ECB`: unpadded, so the input must be block-aligned (checked here
/// as well as in the length query, because an unaligned `NoPadding` encrypt
/// would panic — and rustssm panics abort).
fn ecb_encrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(AES_BLOCK_LENGTH) {
        return None;
    }
    with_aes!(key, C => {
        let encryptor = ecb::Encryptor::<C>::new_from_slice(key).ok()?;
        Some(encryptor.encrypt_padded_vec::<NoPadding>(data))
    })
}

fn ecb_decrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    with_aes!(key, C => {
        let decryptor = ecb::Decryptor::<C>::new_from_slice(key).ok()?;
        decryptor.decrypt_padded_vec::<NoPadding>(data).ok()
    })
}

/// `CKM_AES_CBC` (`pad` false, block-aligned input required) and
/// `CKM_AES_CBC_PAD` (`pad` true, PKCS#7).
fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8], pad: bool) -> Option<Vec<u8>> {
    if !pad && !data.len().is_multiple_of(AES_BLOCK_LENGTH) {
        return None;
    }
    with_aes!(key, C => {
        let encryptor = cbc::Encryptor::<C>::new_from_slices(key, iv).ok()?;
        Some(if pad {
            encryptor.encrypt_padded_vec::<Pkcs7>(data)
        } else {
            encryptor.encrypt_padded_vec::<NoPadding>(data)
        })
    })
}

/// A `None` result on the `pad` path is malformed PKCS#7 padding (or an
/// unaligned ciphertext).
fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8], pad: bool) -> Option<Vec<u8>> {
    with_aes!(key, C => {
        let decryptor = cbc::Decryptor::<C>::new_from_slices(key, iv).ok()?;
        if pad {
            decryptor.decrypt_padded_vec::<Pkcs7>(data).ok()
        } else {
            decryptor.decrypt_padded_vec::<NoPadding>(data).ok()
        }
    })
}

/// `data_length` when it is block-aligned, `None` otherwise.
fn block_aligned(data_length: u64) -> Option<u64> {
    data_length
        .is_multiple_of(AES_BLOCK_LENGTH as u64)
        .then_some(data_length)
}

pub trait Encrypt {
    /// Encrypts `data`, or `None` when the input is unusable for the
    /// mechanism (e.g. unaligned input for an unpadded block mode).
    fn encrypt(self, data: &[u8]) -> Option<Vec<u8>>;

    /// Length of the ciphertext this operation will produce for
    /// `data_length` bytes of plaintext, or `None` when that length is
    /// unusable for the mechanism.
    fn encrypted_length(&self, data_length: u64) -> Option<u64>;
}

pub trait Decrypt {
    /// Decrypts `data`. A `None` result is a mechanism-level rejection: an
    /// authentication-tag mismatch (GCM), malformed padding (CBC-PAD), or an
    /// unaligned ciphertext.
    fn decrypt(self, data: &[u8]) -> Option<Vec<u8>>;

    /// Upper bound on the plaintext length this operation will produce for
    /// `data_length` bytes of ciphertext, or `None` when that length is
    /// unusable for the mechanism. (An upper bound because CBC-PAD strips a
    /// data-dependent amount; the FFI layer reports the exact length after
    /// the operation.)
    fn decrypted_length(&self, data_length: u64) -> Option<u64>;
}

impl Encrypt for Operation {
    fn encrypt(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Operation::EncryptAesGcm {
                key,
                initialization_vector,
                additional_authenticated_data,
            } => {
                let payload = Payload {
                    msg: data,
                    aad: &additional_authenticated_data,
                };
                let iv = &initialization_vector;

                match (key.len(), iv.len()) {
                    (16, 12) => gcm_encrypt::<Aes128Gcm>(&key, iv, payload),
                    (32, 12) => gcm_encrypt::<Aes256Gcm>(&key, iv, payload),
                    (16, 32) => gcm_encrypt::<Aes128Gcm32>(&key, iv, payload),
                    (32, 32) => gcm_encrypt::<Aes256Gcm32>(&key, iv, payload),
                    _ => None,
                }
            }
            Operation::EncryptAesEcb { key } => ecb_encrypt(&key, data),
            Operation::EncryptAesCbc {
                key,
                initialization_vector,
                pad,
            } => cbc_encrypt(&key, &initialization_vector, data, pad),
            _ => None,
        }
    }

    fn encrypted_length(&self, data_length: u64) -> Option<u64> {
        match self {
            Operation::EncryptAesGcm { .. } => data_length.checked_add(AES_GCM_TAG_LENGTH as u64),
            Operation::EncryptAesEcb { .. } | Operation::EncryptAesCbc { pad: false, .. } => block_aligned(data_length),
            // PKCS#7 always pads: up to the next block boundary, or a whole
            // block when already aligned.
            Operation::EncryptAesCbc { pad: true, .. } => (data_length / AES_BLOCK_LENGTH as u64)
                .checked_add(1)?
                .checked_mul(AES_BLOCK_LENGTH as u64),
            _ => None,
        }
    }
}

impl Decrypt for Operation {
    fn decrypt(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Operation::DecryptAesGcm {
                key,
                initialization_vector,
                additional_authenticated_data,
            } => {
                let payload = Payload {
                    msg: data,
                    aad: &additional_authenticated_data,
                };
                let iv = &initialization_vector;

                match (key.len(), iv.len()) {
                    (16, 12) => gcm_decrypt::<Aes128Gcm>(&key, iv, payload),
                    (32, 12) => gcm_decrypt::<Aes256Gcm>(&key, iv, payload),
                    (16, 32) => gcm_decrypt::<Aes128Gcm32>(&key, iv, payload),
                    (32, 32) => gcm_decrypt::<Aes256Gcm32>(&key, iv, payload),
                    _ => None,
                }
            }
            Operation::DecryptAesEcb { key } => ecb_decrypt(&key, data),
            Operation::DecryptAesCbc {
                key,
                initialization_vector,
                pad,
            } => cbc_decrypt(&key, &initialization_vector, data, pad),
            _ => None,
        }
    }

    fn decrypted_length(&self, data_length: u64) -> Option<u64> {
        match self {
            // AES-GCM ciphertext carries a trailing tag, so anything shorter
            // than the tag cannot be valid.
            Operation::DecryptAesGcm { .. } => data_length.checked_sub(AES_GCM_TAG_LENGTH as u64),
            Operation::DecryptAesEcb { .. } | Operation::DecryptAesCbc { pad: false, .. } => block_aligned(data_length),
            // Padded ciphertext is block-aligned and at least one block.
            Operation::DecryptAesCbc { pad: true, .. } => {
                if data_length < AES_BLOCK_LENGTH as u64 {
                    return None;
                }
                block_aligned(data_length)
            }
            _ => None,
        }
    }
}
