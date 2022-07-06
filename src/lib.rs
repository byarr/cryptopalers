use std::cmp::Ordering;
use crate::scoring::Scorer;

mod scoring;

pub fn hex_to_base_64(hex_str: &str) -> String {
    let vec = hex::decode(hex_str).unwrap();
    base64::encode(&vec)
}

pub fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    assert_eq!(b1.len(), b2.len());
    b1.iter().zip(b2.iter()).map(| (b1, b2) | b1 ^ b2).collect()
}

pub fn single_byte_xor(input: &[u8], key: u8) -> Vec<u8> {
    input.iter().map(|b| b ^ key).collect()
}

pub fn guess_single_byte_xor(input: &[u8]) -> Option<(String, f32)> {

    let scorer = scoring::ChiSquaredScorer{};

    (0u8..255u8)
        .map(|key| single_byte_xor(input, key))
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .map(|s| {
            let score = scorer.score(&s);
            (s, score)
        })
        .min_by(|in1, in2| in1.1.partial_cmp(&in2.1).unwrap_or(Ordering::Equal))
}

pub fn detect_single_byte_xor(cipher: &[Vec<u8>]) -> String {
    cipher.iter()
        .filter_map(|c|guess_single_byte_xor(c.as_slice()))
        .min_by(|in1, in2| in1.1.partial_cmp(&in2.1).unwrap_or(Ordering::Equal)).unwrap().0
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::io::BufRead;
    use super::*;

    #[test]
    fn test_hex_to_base_64() {
        assert_eq!(hex_to_base_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string());
    }

    #[test]
    fn test_fixed_xor() {
        let in1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let in2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();


        assert_eq!(fixed_xor(&in1, &in2), expected);
    }

    #[test]
    fn test_guess_single_byte_zor() {
        let in1 = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let res = guess_single_byte_xor(&in1).unwrap();
        assert_eq!(res.0, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn test_detect_single_byte_zor() {
        let file = File::open("./challenge-data/4.txt").unwrap();
        let cipher_texts: Vec<_> = io::BufReader::new(file).lines()
            .filter_map(|l|l.ok())
            .filter_map(|l| hex::decode(l).ok())
            .collect();
        let detected = detect_single_byte_xor(&cipher_texts);
        println!("{}", detected);
    }

}