use openssl::symm::{decrypt, Cipher};
use std::collections::HashMap;

pub fn aes_128_ecb(key: &[u8], input: &[u8]) -> Vec<u8> {
    let t = Cipher::aes_128_ecb();
    

    decrypt(t, key, None, input).unwrap()
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
    fn test_aes_128_ecb() {
        use std::fs::read_to_string;
        let f = read_to_string("./challenge-data/7.txt").unwrap();
        let f: String = f.chars().filter(|c| !c.is_ascii_whitespace()).collect();

        let cipher_text = base64::decode(f).unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();

        let plain_text = aes_128_ecb(key, &cipher_text);

        let plain = String::from_utf8(plain_text).unwrap();

        assert!(plain.starts_with("I'm back and I'm ringin' the bell "));
    }

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
