use rand::Rng;
use crate::block::aes_128_ecb_encrypt;
use crate::block::detect_ecb::HashCount;

const SUFFIX: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

struct Oracle {
    key: [u8; 16],
    suffix: Vec<u8>,
}

impl Oracle {
    fn new() -> Self {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        let suffix = base64::decode(SUFFIX).unwrap();
        Oracle {
            key, suffix
        }
    }

    fn aes_128_ecb(&self, mut input: Vec<u8>) -> Vec<u8> {
        input.extend_from_slice(&self.suffix);
        aes_128_ecb_encrypt(&self.key, input)
    }
}

fn discover_block_size(oracle: &Oracle) -> usize {
    let initial_size = oracle.aes_128_ecb(vec![b'A'; 1]).len();

    (2..64)
        .map(|extra| oracle.aes_128_ecb(vec![b'A'; extra]).len())
        .map(|len| len - initial_size)
        .find(|block| *block != 0)
        .unwrap()
}

fn is_ecb(oracle: &Oracle) -> bool {
    let input = vec![b'A'; 64];
    let cypher = oracle.aes_128_ecb(input);
    HashCount::new(&cypher).max_count() > 1
}

fn byte_at_a_time(oracle: &Oracle) {

    let block_size = discover_block_size(oracle);

    let is_ecb = is_ecb(oracle);


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_block_size() {
        let oracle = Oracle::new();
        assert_eq!(16, discover_block_size(&oracle));
    }

    #[test]
    fn test_is_ecb() {
        let oracle = Oracle::new();
        assert_eq!(true, is_ecb(&oracle));
    }
}