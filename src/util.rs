use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use rand::Rng;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut output = vec![0u8; len];
    rand::thread_rng().fill(&mut output[..]);
    output
}

pub fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

/// Returns `value` as bytes in a fixed-size array, padded with spaces as
/// PKCS#11 requires for character fields. Longer values are truncated.
pub fn padded<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [b' '; N];
    for (i, byte) in value.as_bytes().iter().take(N).enumerate() {
        output[i] = *byte;
    }
    output
}
