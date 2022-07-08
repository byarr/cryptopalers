use openssl::symm::{decrypt, Cipher, encrypt, Crypter, Mode};
use std::collections::HashMap;
use openssl::symm::Mode::{Decrypt, Encrypt};

pub fn aes_128_ecb_decrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    aes_128_ecb(key, input, Decrypt)
}

pub fn aes_128_ecb_encrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    aes_128_ecb(key, input, Encrypt)
}

fn aes_128_ecb(key: &[u8], input: &[u8], mode: Mode) -> Vec<u8> {
    let t = Cipher::aes_128_ecb();
    let mut c = Crypter::new(t, mode, key, None).unwrap();
    c.pad(false);

    let mut out = vec![0; input.len() + t.block_size()];
    let count = c.update(input, &mut out).unwrap();
    let rest = c.finalize(&mut out[count..]).unwrap();
    out.truncate(count + rest);
    out
}

fn xor_in_place(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key)
        .for_each(|(b, k)| *b ^= k);

}

pub fn aes_128_cbc_decrypt(key: &[u8], mut input: Vec<u8>, iv: &[u8]) -> Vec<u8>  {
    let mut result = Vec::new();

    // let padding_bytes = crate::padding::pad(&mut input, 16);

    let num_blocks = input.len() / 16;

    // block 0 decrypt then xor with iv
    // block 1 decrpyt then xor with block 0 (cipher)

    for i in 0..num_blocks {
        let mut plain = aes_128_ecb_decrypt(key, &input[i*16 .. (i+1) * 16]);

        let chain = if i == 0 {
            iv
        } else {
            &input[(i-1)*16 .. i * 16]
        };

        xor_in_place(&mut plain[..], chain);

        result.append(&mut plain);
    }
    // result.truncate(result.len() - padding_bytes);
    result
}


pub fn aes_128_cbc_encrypt(key: &[u8], mut input: Vec<u8>, iv: &[u8]) -> Vec<u8>  {
    let mut result = Vec::new();

    let padding_bytes = crate::padding::pad(&mut input, 16);
    let num_blocks = input.len() / 16;

    // block 0 xor with iv then encrypt
    // block 1 xor with block 0 cipher text then encrypt

    for i in 0..num_blocks {

        let mut input_block: Vec<u8> = input[i*16 .. (i+1) * 16].to_vec(); // todo could be an array

        let chain = if i == 0 {
            iv
        } else {
            &result[(i-1)*16 .. i * 16]
        };
        xor_in_place(&mut input_block[..], chain);
        let mut result_block = aes_128_ecb_encrypt(key, &input_block);
        result.append(&mut result_block);
    }
    result.truncate(result.len() - padding_bytes);
    result
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

        let plain_text = aes_128_ecb_decrypt(key, &cipher_text);

        let plain = String::from_utf8(plain_text).unwrap();

        assert!(plain.starts_with("I'm back and I'm ringin' the bell "));
    }

    #[test]
    fn test_aes_128_ecb_both_ways() {
        use std::fs::read_to_string;
        let f = read_to_string("./challenge-data/7.txt").unwrap();
        let f: String = f.chars().filter(|c| !c.is_ascii_whitespace()).collect();

        let cipher_text = base64::decode(f).unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();


        let plain_text = aes_128_ecb_decrypt(key, &cipher_text);
        let encrypted = aes_128_ecb_encrypt(key, &plain_text);
        assert_eq!(encrypted, cipher_text);


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

    #[test]
    fn test_aes_128_cbc() {
        use std::fs::read_to_string;
        let f = read_to_string("./challenge-data/10.txt").unwrap();
        let f: String = f.chars().filter(|c| !c.is_ascii_whitespace()).collect();

        let cipher_text = base64::decode(f).unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: [u8; 16] = [0;16];

        let plain_text = aes_128_cbc_decrypt(key, cipher_text, &iv);

        let plain = String::from_utf8(plain_text).unwrap();

        assert!(plain.starts_with("I'm back and I'm ringin' the bell "));
    }


    #[test]
    fn test_aes_128_cbc_both_ways() {
        use std::fs::read_to_string;
        let f = read_to_string("./challenge-data/10.txt").unwrap();
        let f: String = f.chars().filter(|c| !c.is_ascii_whitespace()).collect();

        let cipher_text = base64::decode(f).unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: [u8; 16] = [0;16];

        let plain_text = aes_128_cbc_decrypt(key, cipher_text.clone(), &iv);


        let encrypted = aes_128_cbc_encrypt(key, plain_text, &iv);
        assert_eq!(encrypted, cipher_text);
    }
}
