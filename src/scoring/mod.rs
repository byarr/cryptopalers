const EXPECTED_FREQUENCY: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                     // V-Z
];


pub trait Scorer {
    fn score(&self, input: &str) -> f32;
}

pub struct ChiSquaredScorer {

}

impl Scorer for ChiSquaredScorer {
    fn score(&self, input: &str) -> f32 {
        let counts = letter_counts(input);
        let len: u32 = counts.iter().sum();

        (0..26).map(|idx| {
            let observed = counts[idx] as f32;
            let expected = EXPECTED_FREQUENCY[idx] * len as f32;
            let diff = observed - expected;
            (diff * diff) / expected
        }).sum()
    }
}

fn letter_counts(input: &str) -> [u32; 26] {
    let mut result = [0u32; 26];

    input.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .map(|c| c as u8 - b'a')
        .for_each(|idx| result[idx as usize] += 1);


    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_letter_counts() {
        let counts = letter_counts("Hhello!!");
        assert_eq!(counts[0], 0);
        assert_eq!(counts[7], 2);
    }


}