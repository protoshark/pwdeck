use rand::{rngs::OsRng, Rng};

use super::generator::{GeneratorError, PasswordGenerator};

/// Random password generator
pub struct Random {
    /// the password length
    length: usize,
}

impl Random {
    pub fn new(length: usize) -> Self {
        Self { length }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_random() {
        let length = 40;
        let random_password = Random::new(length).generate().unwrap();

        println!("{}", random_password);
        assert_eq!(random_password.len(), length);
    }

    #[test]
    fn short_random() {
        let length = 10;
        let random_password = Random::new(length).generate().unwrap();

        println!("{}", random_password);
        assert_eq!(random_password.len(), length)
    }
}
