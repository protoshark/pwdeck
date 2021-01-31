use std::fs::File;
use std::io::{BufRead, BufReader};

use rand::{
    distributions::{self, Distribution},
    rngs::OsRng,
    Rng,
};

pub enum GenerationMethod {
    Random(usize),
    Diceware(String, usize),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum GeneratorError {
    // just an unknown error for now
    Unknown,
}

/// Generator trait
pub trait PasswordGenerator {
    fn generate(&self) -> Result<String, GeneratorError>;
}

/// Main generator
pub struct Generator {
    generator: Box<dyn PasswordGenerator>,
}

impl Generator {
    pub fn generate(self) -> Result<String, GeneratorError> {
        self.generator.generate()
    }
}

/// Random password generator
struct Random {
    /// the password length
    length: usize,
}

/// Diceware password generator
struct Diceware {
    /// the diceware wordlist path
    source_path: String,
    /// the number of words to generate
    words: usize,
}

impl PasswordGenerator for Random {
    fn generate(&self) -> Result<String, GeneratorError> {
        let special_chars = [
            '!', '#', '$', '%', '&', '*', '+', '-', '_', '.', '/', ':', '=', '?', '~', '`',
        ];

        let mut rng = OsRng::default();
        let mut password = String::new();

        for _ in 0..self.length {
            let r: u8 = rng.gen_range(0..7);

            match r {
                // uppercase
                0..=1 => password.push(rng.gen_range('a'..='z')),
                // lowercase
                2..=3 => password.push(rng.gen_range('A'..='Z')),
                // number
                4..=5 => password.push(char::from(rng.gen_range(48..=57))),
                // special
                6 => {
                    let i = rng.gen_range(0..special_chars.len());
                    password.push(special_chars[i]);
                }
                _ => unreachable!(),
            }
        }

        Ok(password)
    }
}

impl PasswordGenerator for Diceware {
    fn generate(&self) -> Result<String, GeneratorError> {
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

impl From<GenerationMethod> for Generator {
    fn from(method: GenerationMethod) -> Self {
        let generator: Box<dyn PasswordGenerator> = match method {
            GenerationMethod::Random(length) => Box::new(Random { length }),
            GenerationMethod::Diceware(source_path, words) => {
                Box::new(Diceware { source_path, words })
            }
        };

        Self { generator }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random() {
        let password_len = 40;
        let random_password = Random {
            length: password_len,
        }
        .generate()
        .unwrap();

        println!("{}", random_password);
        assert_eq!(random_password.len(), password_len);
    }

    #[test]
    fn test_diceware() {
        let diceware_words = 5;
        let diceware_password = Diceware {
            source_path: String::from("res/diceware_wordlist.txt"),
            words: diceware_words,
        }
        .generate()
        .unwrap();

        println!("{}", diceware_password);
        assert_eq!(diceware_password.split(" ").collect::<Vec<_>>().len(), 5);
    }
}
