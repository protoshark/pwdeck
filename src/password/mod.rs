mod generator;

use generator::{Generator, GenerationMethod};

#[allow(dead_code)]
pub struct PasswordEntry {
    name: String,
    username: String,
    password: String,
}

pub struct PasswordEntryBuilder<'a> {
    name: Option<&'a str>,
    username: Option<&'a str>,
    method: GenerationMethod
}


impl PasswordEntry {
    pub fn new(name: &str, username: &str, password: &str) -> Self {
        // TODO: hash password
        let password = String::from(password);

        Self {
            name: String::from(name),
            username: String::from(username),
            password,
        }
    }
}

impl<'a> PasswordEntryBuilder<'a> {
    pub fn new() -> Self {
        Self {
            name: None,
            username: None,
            method: GenerationMethod::Random(32)
        }
    }

    pub fn build(self) -> PasswordEntry {
        let generator = Generator::from(self.method);
        let password = generator.generate().unwrap();

        PasswordEntry {
            name: String::from(self.name.unwrap()),
            username: String::from(self.username.unwrap()),
            password
        }
    }

    pub fn name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }
    pub fn username(mut self, username: &'a str) -> Self {
        self.username = Some(username);
        self
    }

    pub fn generation_method(mut self, method: GenerationMethod) -> Self {
        self.method = method;
        self
    }
}


