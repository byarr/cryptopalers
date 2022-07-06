pub fn hex_to_base_64(hex_str: &str) -> String {
    let vec = hex::decode(hex_str).unwrap();
    base64::encode(&vec)
}

pub fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    assert_eq!(b1.len(), b2.len());
    b1.iter().zip(b2.iter()).map(| (b1, b2) | b1 ^ b2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_base_64() {
        assert_eq!(hex_to_base_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string());
    }

    #[test]
    fn test_fixed_xor() {
        let in1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let in2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();


        assert_eq!(fixed_xor(&in1, &in2), expected);
    }

}