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

fn byte_at_a_time(oracle: &Oracle) -> Vec<u8> {
    let block_size = discover_block_size(oracle);
    let is_ecb = is_ecb(oracle);


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

    while guessed_data.len() < 16 {

        let padding = block_size - byte_num ;

        let input = vec![b'A'; padding];
        let oracle_enc = oracle.aes_128_ecb(input);

        for i in 0..255 {
            let mut test_input = vec![b'A'; padding];
            test_input.extend_from_slice(&guessed_data);

            test_input.push(i);
            let test_enc = oracle.aes_128_ecb(test_input);

            if (test_enc[0..block_size] == oracle_enc[0..block_size]) {
                guessed_data.push(i);

                println!("Found it {} {}", i, i as char);
                break;
            }

        }

        byte_num += 1;


    }


    guessed_data
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

    #[test]
    fn test_byte_at_atime() {
        let oracle = Oracle::new();
        let data = byte_at_a_time(&oracle);
        for i in 0..data.len() {
            assert_eq!(data[i], oracle.suffix[i]);
        }
    }
}