
use std::collections::HashMap;
use openssl::rand::rand_bytes;

use rand::{Rng, thread_rng};
use crate::block::{aes_128_cbc_encrypt, aes_128_ecb_encrypt};


fn encryption_oracle(mut input: Vec<u8>) -> Vec<u8> {
    let mut key: [u8; 16] = [0; 16];
    rand_bytes(&mut key).unwrap();

    let mut padded_input = Vec::with_capacity(input.len() + 20);
    let prefix_len = rand::thread_rng().gen_range(5..10);
    let suffix_len = rand::thread_rng().gen_range(5..10);
    for _i in 0..prefix_len {
        padded_input.push(rand::thread_rng().gen());
    }
    padded_input.append(&mut input);
    for _i in 0..suffix_len {
        padded_input.push(rand::thread_rng().gen());
    }

    let mode: bool = thread_rng().gen();
    if mode {
        aes_128_ecb_encrypt(&key, &padded_input)
    } else {
        let mut iv: [u8; 16] = [0; 16];
        rand_bytes(&mut iv).unwrap();
        aes_128_cbc_encrypt(&key, input, &iv)
    }
}



pub fn detect_aes_128_ecb(possible_cipher_texts: Vec<Vec<u8>>) -> (usize, i32) {
    fn hash_block(block: &[u8]) -> u128 {
        let mut b_hash: u128 = 0;
        block.iter().for_each(|b| {
            b_hash <<= 8;
            b_hash |= *b as u128;
        });
        b_hash
    }

    let block_size_bytes = 16;

    possible_cipher_texts
        .iter()
        .enumerate()
        .filter_map(|(idx, cipher_text)| {
            let num_blocks = cipher_text.len() / block_size_bytes;

            let counts = (0..num_blocks)
                .map(|b| hash_block(&cipher_text[b * block_size_bytes..(b + 1) * block_size_bytes]))
                .fold(HashMap::new(), |mut acc, i| {
                    let entry = acc.entry(i).or_insert(0);
                    *entry += 1;
                    acc
                });

            counts.values().max().map(|m| (idx, *m))
        })
        .max_by(|b1, b2| b1.1.cmp(&b2.1))
        .unwrap()
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
        assert_eq!(idx.1, 4);
    }
}
