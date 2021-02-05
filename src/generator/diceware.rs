use std::fs::File;
use std::io::{BufRead, BufReader};

use rand::distributions::{self, Distribution};
use rand::rngs::OsRng;

use super::PasswordGenerator;
use crate::password::PasswordError;

/// Diceware password generator
pub struct Diceware {
    /// the diceware wordlist path
    source_path: String,
    /// the number of words to generate
    words: usize,
}

impl Diceware {
    pub fn new(source_path: String, words: usize) -> Self {
        Self { source_path, words }
    }
}

impl PasswordGenerator for Diceware {
    fn generate(&self) -> Result<String, PasswordError> {
        let wordlist_file =
            File::open(&self.source_path).expect("Can't open the diceware wordlist");
        let lines: Vec<String> = BufReader::new(&wordlist_file)
            .lines()
            .map(|l| l.unwrap())
            .collect();

        let mut rng = OsRng::default();
        let mut password = String::new();

        for _ in 0..self.words {
            // roll the dices
            let dices = distributions::Uniform::new_inclusive(0, 5);
            let dices: Vec<usize> = dices.sample_iter(&mut rng).take(5).collect();

            let line = dices[4] + dices[3] * 6 + dices[2] * 36 + dices[1] * 216 + dices[0] * 1296;

            password.push_str(&lines[line]);
            password.push(' ');
        }
        password.pop();

        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_words() {
        let diceware_words = 5;
        let diceware_password = Diceware {
            source_path: String::from("res/diceware_wordlist.txt"),
            words: diceware_words,
        }
        .generate()
        .unwrap();

        println!("{}", diceware_password);
        assert_eq!(
            diceware_password.split(" ").collect::<Vec<_>>().len(),
            diceware_words
        );
    }
}
