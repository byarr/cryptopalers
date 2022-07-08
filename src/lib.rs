use crate::scoring::{ChiSquaredScore, Scorer};

pub mod scoring;
pub mod xor;
pub mod block;

pub fn hex_to_base_64(hex_str: &str) -> String {
    let vec = hex::decode(hex_str).unwrap();
    base64::encode(&vec)
}

pub fn hamming_distance(in1: &[u8], in2: &[u8]) -> u32 {
    in1.iter()
        .zip(in2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .map(|b| b.count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_base_64() {
        assert_eq!(hex_to_base_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string());
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
            37
        );
    }
}
