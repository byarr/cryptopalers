use crate::block::aes_128_ecb_encrypt;
use crate::block::byte_at_a_time_simple::{discover_block_size, SUFFIX};
use crate::block::detect_ecb::HashCount;
use rand::Rng;

struct Oracle {
    prefix: Vec<u8>,
    key: [u8; 16],
    suffix: Vec<u8>,
}

impl Oracle {
    fn new() -> Self {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        let suffix = base64::decode(SUFFIX).unwrap();

        let prefix_length = rand::thread_rng().gen_range(2..32);
        let mut prefix = vec![0u8; prefix_length];
        rand::thread_rng().fill(&mut prefix[..]);

        Oracle {
            key,
            suffix,
            prefix,
        }
    }

    fn aes_128_ecb(&self, input: Vec<u8>) -> Vec<u8> {
        let mut payload = Vec::with_capacity(input.len() + self.prefix.len() + self.suffix.len());
        payload.extend_from_slice(&self.prefix);
        payload.extend_from_slice(&input);
        payload.extend_from_slice(&self.suffix);

        aes_128_ecb_encrypt(&self.key, payload)
    }
}

fn find_repeating_blocks(data: &[u8]) -> Option<usize> {
    let num_blocks = data.len() / 16;
    for i in 0..num_blocks - 1 {
        if data[i * 16..(i + 1) * 16] == data[(i + 1) * 16..(i + 2) * 16] {
            return Some(i);
        }
    }
    None
}

// guess size of prefix
// send in 2 identical blocks - if they appear at block 2 then we know 1 block of prefix
// keep adding bytes until we detect it
fn discover_prefix_len<F: Fn(Vec<u8>) -> Vec<u8>>(oracle: F) -> usize {
    let (bytes, block_num) = (32..48)
        .filter_map(|bytes| {
            let input = vec![0xAA; bytes];
            let output = oracle(input);
            find_repeating_blocks(&output).map(|block_num| (bytes, block_num))
        })
        .next()
        .unwrap();

    // after injected `bytes` our duplicate data appeared at block_num * 16
    // so the prefix = (block_num-1)*16 - (bytes - 32)

    (block_num) * 16 - (bytes - 32)
}

fn byte_at_a_time<F: Fn(Vec<u8>) -> Vec<u8>>(oracle: F) -> Vec<u8> {
    let (block_size, num_bytes) = discover_block_size(|inp| oracle(inp));

    let prefix_len = discover_prefix_len(&oracle);

    println!("{:?}", prefix_len);

    // use existing code but pad input with enough input to take prefix to full block and remove from output
    let padding_len = 16 - (prefix_len % 16);
    let prefix_to_strip = (prefix_len + padding_len);

    crate::block::byte_at_a_time_simple::byte_at_a_time(|input| {
        let mut padded_input = Vec::with_capacity(input.len() + padding_len);
        for i in 0..padding_len {
            padded_input.push(0u8);
        }
        padded_input.extend_from_slice(&input);

        let output = oracle(padded_input);

        let mut stripped_output = Vec::new();
        stripped_output.extend_from_slice(&output[prefix_to_strip..]);

        stripped_output
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::byte_at_a_time_simple::discover_block_size;

    #[test]
    fn test_discover_block_size() {
        let oracle = Oracle::new();
        let (block_size, data_length) = discover_block_size(|input| oracle.aes_128_ecb(input));
        assert_eq!(16, block_size);
        assert_eq!(oracle.suffix.len() + oracle.prefix.len(), data_length);
    }

    #[test]
    fn test_discover_prefix_len() {
        for _i in 0..32 {
            let oracle = Oracle::new();
            let prefix_len = discover_prefix_len(|input| oracle.aes_128_ecb(input));
            assert_eq!(prefix_len, oracle.prefix.len());
        }
    }

    #[test]
    fn test_byte_at_atime() {
        let oracle = Oracle::new();
        let data = byte_at_a_time(|inp| oracle.aes_128_ecb(inp));

        assert_eq!(data.len(), oracle.suffix.len());

        for i in 0..oracle.suffix.len() {
            assert_eq!(data[i], oracle.suffix[i]);
        }
    }
}
