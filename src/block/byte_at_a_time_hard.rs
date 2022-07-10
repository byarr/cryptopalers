use crate::block::aes_128_ecb_encrypt;
use crate::block::detect_ecb::HashCount;
use rand::Rng;
use crate::block::byte_at_a_time_simple::SUFFIX;


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


        Oracle { key, suffix, prefix }
    }

    fn aes_128_ecb(&self, input: Vec<u8>) -> Vec<u8> {

        let mut payload = Vec::with_capacity(input.len() + self.prefix.len() + self.suffix.len());
        payload.extend_from_slice(&self.prefix);
        payload.extend_from_slice(&input);
        payload.extend_from_slice(&self.suffix);

        aes_128_ecb_encrypt(&self.key, payload)
    }
}





#[cfg(test)]
mod tests {
    use crate::block::byte_at_a_time_simple::discover_block_size;
    use super::*;

    #[test]
    fn test_discover_block_size() {
        let oracle = Oracle::new();
        let (block_size, data_length) = discover_block_size(|input| oracle.aes_128_ecb(input));
        assert_eq!(16, block_size);
        assert_eq!(oracle.suffix.len() + oracle.prefix.len(), data_length);
    }

    // #[test]
    // fn test_is_ecb() {
    //     let oracle = Oracle::new();
    //     assert_eq!(true, is_ecb(&oracle));
    // }

    // #[test]
    // fn test_byte_at_atime() {
    //     let oracle = Oracle::new();
    //     let data = byte_at_a_time(&oracle);
    //
    //     assert_eq!(data.len(), oracle.suffix.len());
    //
    //     for i in 0..oracle.suffix.len() {
    //         assert_eq!(data[i], oracle.suffix[i]);
    //     }
    // }
}
