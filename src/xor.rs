use crate::scoring::ScoredDecrypt;
use crate::{scoring, ChiSquaredScore, Scorer};
use std::cmp::Ordering;

pub fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    assert_eq!(b1.len(), b2.len());
    b1.iter().zip(b2.iter()).map(|(b1, b2)| b1 ^ b2).collect()
}

pub fn single_byte_xor(input: &[u8], key: u8) -> Vec<u8> {
    input.iter().map(|b| b ^ key).collect()
}

pub fn repeating_key_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

pub fn guess_single_byte_xor(input: &[u8]) -> Vec<ScoredDecrypt> {
    let scorer = scoring::ChiSquaredScorer {};

    let mut result: Vec<_> = (0u8..255u8)
        .map(|key| single_byte_xor(input, key))
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .map(|s| {
            let score = scorer.score(&s);
            (s, score)
        })
        .filter(|s| s.1.unprintable == 0)
        .collect();

    result.sort_by(compare_scores);

    result
}

pub fn detect_single_byte_xor(cipher: &[Vec<u8>]) -> Vec<ScoredDecrypt> {
    let mut result: Vec<_> = cipher
        .iter()
        .flat_map(|c| guess_single_byte_xor(c.as_slice()).into_iter())
        .collect();

    result.sort_by(compare_scores);
    result
}

fn weighted_chi(chi: &ChiSquaredScore) -> f32 {
    chi.chi * chi.other_printable as f32
}

fn compare_scores(in1: &ScoredDecrypt, in2: &ScoredDecrypt) -> Ordering {
    weighted_chi(&in1.1)
        .partial_cmp(&weighted_chi(&in2.1))
        .unwrap_or(Ordering::Equal)
}

fn break_repeated_key_xor(input: &[u8]) {
    // find a key size or key sizes using hamming distance

    // given a key size (maybe more than one) - split input into key size number of chunks and xor solve them



}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io;
    use std::io::BufRead;

    #[test]
    fn test_fixed_xor() {
        let in1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let in2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(fixed_xor(&in1, &in2), expected);
    }

    #[test]
    fn test_guess_single_byte_zor() {
        let in1 =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let res = guess_single_byte_xor(&in1);
        assert_eq!(res[0].0, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn test_detect_single_byte_zor() {
        let file = File::open("./challenge-data/4.txt").unwrap();
        let cipher_texts: Vec<_> = io::BufReader::new(file)
            .lines()
            .filter_map(|l| l.ok())
            .filter_map(|l| hex::decode(l).ok())
            .collect();
        let detected = detect_single_byte_xor(&cipher_texts);

        assert_eq!(detected[0].0, "Now that the party is jumping\n");
    }

    #[test]
    fn test_repeating_key_xor() {
        let in1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";

        let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        assert_eq!(
            repeating_key_xor(in1.as_bytes(), key.as_bytes()),
            hex::decode(expected_hex).unwrap()
        );
    }
}
