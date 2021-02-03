use crate::password::PasswordError;

mod diceware;
mod random;

use diceware::*;
use random::*;

pub enum GenerationMethod {
    Random(usize),
    Diceware(String, usize),
}

/// Generator trait
pub trait PasswordGenerator {
    fn generate(&self) -> Result<String, PasswordError>;
}

/// Password Generator
pub struct Generator {
    generator: Box<dyn PasswordGenerator>,
}

impl Generator {
    pub fn generate(self) -> Result<String, PasswordError> {
        self.generator.generate()
    }
}

impl From<GenerationMethod> for Generator {
    fn from(method: GenerationMethod) -> Self {
        match method {
            GenerationMethod::Random(length) => {
                let generator = Box::new(Random::new(length));
                Self { generator }
            }
            GenerationMethod::Diceware(source_path, words) => {
                let generator = Box::new(Diceware::new(source_path, words));
                Self { generator }
            }
        }
    }
}
