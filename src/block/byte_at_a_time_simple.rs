use crate::block::aes_128_ecb_encrypt;
use crate::block::detect_ecb::HashCount;
use rand::Rng;

const SUFFIX: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

struct Oracle {
    key: [u8; 16],
    suffix: Vec<u8>,
}

impl Oracle {
    fn new() -> Self {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        let suffix = base64::decode(SUFFIX).unwrap();
        Oracle { key, suffix }
    }

    fn aes_128_ecb(&self, mut input: Vec<u8>) -> Vec<u8> {
        input.extend_from_slice(&self.suffix);
        aes_128_ecb_encrypt(&self.key, input)
    }
}

fn discover_block_size(oracle: &Oracle) -> (usize, usize) {
    let initial_size = oracle.aes_128_ecb(vec![b'A'; 1]).len(); // Oracle + 1 + padding (1 - block_size)

    let (bytes, enc_length) = (2..64)
        .map(|extra| (extra, oracle.aes_128_ecb(vec![b'A'; extra]).len()))
        .find(|(_data_len, encrypted_len)| (encrypted_len - initial_size) != 0)
        .unwrap();

    // enc_length = Oracale + bytes + padd (1- blocksize)

    let block_size = enc_length - initial_size;

    let data_length = initial_size - bytes;

    (block_size, data_length)
}

fn is_ecb(oracle: &Oracle) -> bool {
    let input = vec![b'A'; 64];
    let cypher = oracle.aes_128_ecb(input);
    HashCount::new(&cypher).max_count() > 1
}

fn byte_at_a_time(oracle: &Oracle) -> Vec<u8> {
    let (block_size, num_bytes) = discover_block_size(oracle);
    let _is_ecb = is_ecb(oracle);

    // let's use a block size of 4
    // if we pass in AAA then oracle will ecncrpt AAA1 2345 6789                     block_num 0, byte_num 1
    // if we pass in AAAB then oracle will ecncrpt AAAB 1234 5678
    // if we vary B until the block matches then we know the vlaue of B should be 1
    // for byte 2 pass AA then orcale will encrypt AA12 3456                          block_num 0, byte_num 1
    // then we can guess AA1Y to find 2

    // second block:
    // pass in AAA  == AAA1 2345 of which only the 5 is unknown to me
    // AAA1 234X - match second block

    let mut guessed_data = Vec::new();

    let mut block_num = 0;
    let mut byte_num = 1; // we want the first byte

    while guessed_data.len() < num_bytes {
        let padding = block_size - byte_num;

        let input = vec![b'A'; padding];
        let oracle_enc = oracle.aes_128_ecb(input);

        let b = (0u8..255)
            .find(|i| {
                let mut test_input = vec![b'A'; padding];
                test_input.extend_from_slice(&guessed_data);

                test_input.push(*i);
                let test_enc = oracle.aes_128_ecb(test_input);

                test_enc[block_num * block_size..(block_num + 1) * block_size]
                    == oracle_enc[block_num * block_size..(block_num + 1) * block_size]
            })
            .unwrap();

        guessed_data.push(b);

        byte_num += 1;
        if byte_num > 16 {
            byte_num = 1;
            block_num += 1;
        }
    }
    guessed_data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_block_size() {
        let oracle = Oracle::new();
        let (block_size, data_length) = discover_block_size(&oracle);
        assert_eq!(16, block_size);
        assert_eq!(oracle.suffix.len(), data_length);
    }

    #[test]
    fn test_is_ecb() {
        let oracle = Oracle::new();
        assert_eq!(true, is_ecb(&oracle));
    }

    #[test]
    fn test_byte_at_atime() {
        let oracle = Oracle::new();
        let data = byte_at_a_time(&oracle);

        assert_eq!(data.len(), oracle.suffix.len());

        for i in 0..oracle.suffix.len() {
            assert_eq!(data[i], oracle.suffix[i]);
        }
    }
}
