use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use rand::Rng;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut output = vec![0u8; len];
    rand::rng().fill_bytes(&mut output);
    output
}

pub fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
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
