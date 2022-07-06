const EXPECTED_FREQUENCY: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, // V-Z
];

pub type ScoredDecrypt = (String, ChiSquaredScore);

pub trait Scorer {
    fn score(&self, input: &str) -> ChiSquaredScore;
}

pub struct ChiSquaredScorer {}

impl Scorer for ChiSquaredScorer {
    fn score(&self, input: &str) -> ChiSquaredScore {
        let counts = letter_counts(input);

        let len: u32 = counts.total();

        let chi = (0..26)
            .map(|idx| {
                let observed = counts.counts[idx] as f32;
                let expected = EXPECTED_FREQUENCY[idx] * len as f32;
                let diff = observed - expected;
                (diff * diff) / expected
            })
            .sum();

        ChiSquaredScore {
            chi,
            other_printable: counts.other_printable,
            unprintable: counts.unprintable,
        }
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ChiSquaredScore {
    pub chi: f32,
    pub other_printable: u32,
    pub unprintable: u32,
}

#[derive(Debug, Default)]
pub struct LetterCounts {
    counts: [u32; 26],
    other_printable: u32,
    unprintable: u32,
}

impl LetterCounts {
    fn add(&mut self, c: char) {
        match c {
            letter if letter.is_ascii_alphabetic() => {
                let lower = letter.to_ascii_lowercase();
                let idx = lower as u8 - b'a';
                self.counts[idx as usize] += 1;
            }
            other_printable
                if other_printable.is_ascii_punctuation()
                    || other_printable.is_ascii_digit()
                    || other_printable.is_ascii_whitespace() =>
            {
                self.other_printable += 1;
            }
            _ => self.unprintable += 1,
        };
    }

    fn total(&self) -> u32 {
        self.counts.iter().sum()
    }
}

fn letter_counts(input: &str) -> LetterCounts {
    input.chars().fold(LetterCounts::default(), |mut acc, c| {
        acc.add(c);
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_letter_counts() {
        let counts = letter_counts("Hhello!!");
        assert_eq!(counts.counts[0], 0);
        assert_eq!(counts.counts[7], 2);
        assert_eq!(counts.total(), 6);
    }
}
