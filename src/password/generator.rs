use super::diceware::Diceware;
use super::random::Random;

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
