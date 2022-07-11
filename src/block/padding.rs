fn calc_padding(data: &[u8], block_size: usize) -> usize {
    block_size - (data.len() % block_size)
}

pub fn pad(data: &mut Vec<u8>, block_size: usize) -> usize {
    let padding = calc_padding(data, block_size);
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

    if data
        .iter()
        .rev()
        .take(padding as usize)
        .cloned()
        .all(|p| p == padding)
    {
        data.truncate(data.len() - padding as usize);
    }
}

pub fn validate_padding(data: &[u8], block_size: usize) -> Result<&[u8], ()> {
    if data.len() % block_size != 0 {
        return Err(());
    }

    let padding = *data.last().unwrap();
    if padding as usize > block_size {
        return Err(());
    }

    if !data
        .iter()
        .rev()
        .take(padding as usize)
        .cloned()
        .all(|p| p == padding)
    {
        return Err(())
    }

    return Ok(&data[0..data.len()-padding as usize])
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

        assert_eq!(
            data,
            Vec::from("YELLOW_SUBMARINE\x04\x04\x04\x04".as_bytes())
        );
    }

    #[test]
    fn test_validate_padding() {
        let valid = "ICE ICE BABY\x04\x04\x04\x04";
        let expected = "ICE ICE BABY";

        assert_eq!(validate_padding(valid.as_bytes(), 16), Ok(expected.as_bytes()));

        for invalid in ["ICE ICE BABY\x05\x05\x05\x05", "ICE ICE BABY\x01\x02\x03\x04"] {
            assert!(validate_padding(invalid.as_bytes(), 16).is_err());
        }
    }
}
