use openssl::symm::{Cipher, Crypter, Mode};

use crate::block::padding::strip_padding;
use openssl::symm::Mode::{Decrypt, Encrypt};

const BLOCK_SIZE: usize = 16;

pub fn aes_128_ecb_decrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let num_blocks = input.len() / BLOCK_SIZE;

    for i in 0..num_blocks {
        let mut block_out =
            aes_128_ecb_block(key, &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE], Decrypt);
        output.append(&mut block_out);
    }

    strip_padding(&mut output, BLOCK_SIZE);
    output
}

pub fn aes_128_ecb_encrypt(key: &[u8], mut input: Vec<u8>) -> Vec<u8> {
    let padding_bytes = crate::block::padding::pad(&mut input, BLOCK_SIZE);
    let mut output = Vec::with_capacity(input.len() + padding_bytes);

    let num_blocks = input.len() / 16;
    for i in 0..num_blocks {
        let mut block_out =
            aes_128_ecb_block(key, &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE], Encrypt);
        output.append(&mut block_out);
    }
    output
}

fn aes_128_ecb_block(key: &[u8], input: &[u8], mode: Mode) -> Vec<u8> {
    assert_eq!(input.len(), BLOCK_SIZE);

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
    data.iter_mut().zip(key).for_each(|(b, k)| *b ^= k);
}

pub fn aes_128_cbc_decrypt(key: &[u8], input: Vec<u8>, iv: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    let num_blocks = input.len() / 16;

    // block 0 decrypt then xor with iv
    // block 1 decrpyt then xor with block 0 (cipher)

    for i in 0..num_blocks {
        let mut plain = aes_128_ecb_block(
            key,
            &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
            Mode::Decrypt,
        );

        let chain = if i == 0 {
            iv
        } else {
            &input[(i - 1) * BLOCK_SIZE..i * BLOCK_SIZE]
        };

        xor_in_place(&mut plain[..], chain);

        result.append(&mut plain);
    }

    strip_padding(&mut result, BLOCK_SIZE);
    result
}

pub fn aes_128_cbc_encrypt(key: &[u8], mut input: Vec<u8>, iv: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    let _padding_bytes = crate::block::padding::pad(&mut input, BLOCK_SIZE);
    let num_blocks = input.len() / 16;

    // block 0 xor with iv then encrypt
    // block 1 xor with block 0 cipher text then encrypt

    for i in 0..num_blocks {
        let mut input_block: Vec<u8> = input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].to_vec(); // todo could be an array

        let chain = if i == 0 {
            iv
        } else {
            &result[(i - 1) * BLOCK_SIZE..i * BLOCK_SIZE]
        };
        xor_in_place(&mut input_block[..], chain);
        let mut result_block = aes_128_ecb_block(key, &input_block, Encrypt);
        result.append(&mut result_block);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let encrypted = aes_128_ecb_encrypt(key, plain_text.clone());
        assert_eq!(encrypted, cipher_text);

        let plain = String::from_utf8(plain_text).unwrap();

        assert!(plain.starts_with("I'm back and I'm ringin' the bell "));
    }

    #[test]
    fn test_aes_128_cbc() {
        use std::fs::read_to_string;
        let f = read_to_string("./challenge-data/10.txt").unwrap();
        let f: String = f.chars().filter(|c| !c.is_ascii_whitespace()).collect();

        let cipher_text = base64::decode(f).unwrap();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: [u8; 16] = [0; 16];

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
        let iv: [u8; 16] = [0; 16];

        let plain_text = aes_128_cbc_decrypt(key, cipher_text.clone(), &iv);

        let encrypted = aes_128_cbc_encrypt(key, plain_text, &iv);
        assert_eq!(encrypted, cipher_text);
    }
}
