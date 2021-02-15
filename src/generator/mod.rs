use crate::{password::PasswordError, security::SecString};

mod diceware;
mod random;

use diceware::Diceware;
use random::Random;

/// Generator trait
pub trait PasswordGenerator {
    fn generate(&self) -> Result<SecString, PasswordError>;
}

pub enum GenerationMethod {
    Random(usize),
    Diceware(String, usize),
}

/// Password Generator
pub struct Generator {
    generator: Box<dyn PasswordGenerator>,
}

impl Generator {
    pub fn new(generator: Box<dyn PasswordGenerator>) -> Self {
        Self { generator }
    }

    pub fn password(self) -> Result<SecString, PasswordError> {
        self.generator.generate()
    }
}

impl From<GenerationMethod> for Generator {
    fn from(method: GenerationMethod) -> Self {
        let generator: Box<dyn PasswordGenerator> = match method {
            GenerationMethod::Random(len) => Box::new(Random::new(len)),
            GenerationMethod::Diceware(wordlist, len) => Box::new(Diceware::new(wordlist, len)),
        };

        Self::new(generator)
    }
}
