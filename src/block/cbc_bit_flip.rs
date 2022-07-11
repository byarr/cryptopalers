use crate::block::padding::strip_padding;
use crate::block::{aes_128_cbc_decrypt, aes_128_cbc_encrypt};
use rand::{thread_rng, Rng};
use std::string::FromUtf8Error;

struct CbcCookieCutter {
    key: [u8; 16],
    iv: [u8; 16],
}

impl Default for CbcCookieCutter {
    fn default() -> Self {
        let mut key = [0; 16];
        thread_rng().fill(&mut key);

        let mut iv = [0; 16];
        thread_rng().fill(&mut iv);

        CbcCookieCutter { key, iv }
    }
}

impl CbcCookieCutter {
    fn make_cookie(&self, user_data: &str) -> Vec<u8> {
        let sanitised_input = user_data.replace(';', "%3B").replace('=', "%3D");
        let cookie_string = format!("comment1=cooking%20MCs;userdata={sanitised_input};comment2=%20like%20a%20pound%20of%20bacon");
        let cookie_bytes = cookie_string.into_bytes();
        aes_128_cbc_encrypt(&self.key, cookie_bytes, &self.iv)
    }

    fn is_admin(&self, cookie: &[u8]) -> bool {
        let decrypt = aes_128_cbc_decrypt(&self.key, cookie.to_vec(), &self.iv);

        let result = String::from_utf8_lossy(&decrypt);
        result.contains(";admin=true;")
    }
}

fn flip_my_bits(oracle: &CbcCookieCutter) -> Vec<u8> {
    let padding_byte = b'A';

    // block of data for us to mangle
    let mut input = vec![padding_byte; 16];

    // block we want to manipulate
    let desired_input = ";admin=true";

    let num_pad = 16 - desired_input.len();
    for _i in 0..num_pad {
        input.push(padding_byte);
    }
    input.extend_from_slice(desired_input.as_bytes());

    // flip a bit in our taregt input to hide the';' and '='
    input[16 + num_pad + desired_input.find(';').unwrap()] ^= 0b0000001;
    input[16 + num_pad + desired_input.find('=').unwrap()] ^= 0b0000001;

    let mut valid_non_admin_cookie = oracle.make_cookie(&String::from_utf8(input).unwrap());

    // flip a bit in the block before the target - this is the full data with 2 blocks of prefix
    valid_non_admin_cookie[32 + num_pad + desired_input.find(';').unwrap()] ^= 0b0000001;
    valid_non_admin_cookie[32 + num_pad + desired_input.find('=').unwrap()] ^= 0b0000001;

    valid_non_admin_cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flip_my_bits() {
        let oracle = CbcCookieCutter::default();
        let my_bits = flip_my_bits(&oracle);
        assert!(oracle.is_admin(&my_bits))
    }
}
