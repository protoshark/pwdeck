// TODO move generator to a separated module
use super::{PasswordError, random::Random, diceware::Diceware};

pub enum GenerationMethod {
    Random(usize),
    Diceware(String, usize),
}

/// Generator trait
pub trait PasswordGenerator {
    fn generate(&self) -> Result<String, PasswordError>;
}

/// Main generator
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
        let generator: Box<dyn PasswordGenerator> = match method {
            GenerationMethod::Random(length) => Box::new(Random::new(length)),
            GenerationMethod::Diceware(source_path, words) => {
                Box::new(Diceware::new(source_path, words))
            }
        };

        Self { generator }
    }
}
