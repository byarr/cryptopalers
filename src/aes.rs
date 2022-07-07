use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, decrypt, Mode};

pub fn aes_128_ecb(key: &[u8], input: &[u8]) -> Vec<u8> {
    let t = Cipher::aes_128_ecb();
    let plain = decrypt(
        t,
        key,
        None,
        input).unwrap();

    plain
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
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

        println!("{}", plain);
        assert!(plain.starts_with("I'm back and I'm ringin' the bell "));
    }
}