fn calc_padding(data: &[u8], block_size: usize) -> usize {
    block_size-(data.len() %  block_size)
}

pub fn pad(data: &mut Vec<u8>, block_size: usize) -> usize  {
    let padding = calc_padding(data, block_size) ;
    for _i in 0..padding {
        data.push(padding as u8);
    }
    padding
}

pub fn strip_padding(data: &mut Vec<u8>, block_size: usize) {
    if data.len() % block_size != 0 {
        return;
    }

    let padding = *data.last().unwrap();
    if padding as usize > block_size {
        return;
    }

    if data.iter().rev().take(padding as usize).cloned().all(|p| p == padding) {
        data.truncate(data.len() - padding as usize);
    }



}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_padding() {
        assert_eq!(4, calc_padding("YELLOW SUBMARINE".as_bytes(), 20));
        assert_eq!(20, calc_padding("YELLOW SUBMARINE1234".as_bytes(), 20));
    }

    #[test]
    fn test_pad() {
        let mut data = Vec::from("YELLOW_SUBMARINE".as_bytes());
        pad(&mut data, 20);

        assert_eq!(data, Vec::from("YELLOW_SUBMARINE\x04\x04\x04\x04".as_bytes()));
    }
}