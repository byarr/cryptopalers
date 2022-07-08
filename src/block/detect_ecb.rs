use std::collections::HashMap;
use openssl::rand::rand_bytes;

use rand::{Rng, thread_rng};
use crate::block::{aes_128_cbc_encrypt, aes_128_ecb_encrypt};

#[derive(Debug, Default)]
pub struct HashCount(HashMap<u128, i32>);

impl HashCount {

    fn new(data: &[u8]) -> Self {
        let block_size_bytes = 16;
        let num_blocks = data.len() / block_size_bytes;

        let counts = (0..num_blocks)
            .fold(HashCount::default(), |mut acc, i| {
                acc.add_block(&data[i * block_size_bytes..(i + 1) * block_size_bytes]);
                acc
            });
        counts
    }

    fn hash_block(block: &[u8]) -> u128 {
        let mut b_hash: u128 = 0;
        block.iter().for_each(|b| {
            b_hash <<= 8;
            b_hash |= *b as u128;
        });
        b_hash
    }

    fn add_block(&mut self, block: &[u8]) {
        let hash = HashCount::hash_block(block);
        let entry = self.0.entry(hash).or_insert(0);
        *entry += 1;
    }

    fn max_count(&self) -> i32 {
        *self.0.values().max().unwrap_or(&0)
    }

}

pub fn detect_aes_128_ecb(possible_cipher_texts: Vec<Vec<u8>>) -> (usize, HashCount) {
    possible_cipher_texts
        .iter()
        .enumerate()
        .map(|(idx, cipher_text)| (idx, HashCount::new(cipher_text)))
        .max_by_key(|(idx, count)| count.max_count())
        .unwrap()
}


fn encryption_oracle(mut input: Vec<u8>) -> Vec<u8> {
    leaky_encryption_oracle(input).0
}

fn leaky_encryption_oracle(mut input: Vec<u8>) -> (Vec<u8>, bool) {
    let mut key: [u8; 16] = [0; 16];
    rand_bytes(&mut key).unwrap();

    let mut padded_input = Vec::with_capacity(input.len() + 20);
    let prefix_len = thread_rng().gen_range(5..10);
    let suffix_len = thread_rng().gen_range(5..10);
    for _i in 0..prefix_len {
        padded_input.push(rand::thread_rng().gen());
    }
    padded_input.append(&mut input);
    for _i in 0..suffix_len {
        padded_input.push(rand::thread_rng().gen());
    }

    let use_ecb: bool = thread_rng().gen();
    if use_ecb {
        (aes_128_ecb_encrypt(&key, padded_input), use_ecb)
    } else {
        let mut iv: [u8; 16] = [0; 16];
        rand_bytes(&mut iv).unwrap();
        (aes_128_cbc_encrypt(&key, input, &iv), use_ecb)
    }
}

fn detect_ecb_cbc() -> (bool, bool) {
    // need two identical plain text blocks - but the oracle is going to prepend some data - so pass in more and ignore first block

    let mut v = vec![0xff; 64];

    let (cipher_text, was_ecb) = leaky_encryption_oracle(v);

    let detected_ecb = HashCount::new(&cipher_text).max_count() > 1;

    return (was_ecb, detected_ecb)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::io::BufRead;

    #[test]
    fn test_detect_aes_128_ecb() {
        let data: Vec<_> =
            io::BufReader::new(std::fs::File::open("./challenge-data/8.txt").unwrap())
                .lines()
                .filter_map(|r| r.ok())
                .map(|s| hex::decode(s).unwrap())
                .collect();

        let idx = detect_aes_128_ecb(data);
        assert_eq!(idx.1.max_count(), 4);
    }

    #[test]
    fn test_detect_ecb_cbc() {
        for i in 0..10 {
            let (was, detect) = detect_ecb_cbc();
            assert_eq!(was, detect)

        }
    }
}
