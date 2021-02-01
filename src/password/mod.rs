use serde::{Serialize, Deserialize};

pub mod generator;
pub(self) mod diceware;
pub(self) mod random;

pub use generator::{GenerationMethod, Generator};

#[allow(dead_code)]
#[derive(Debug)]
pub enum PasswordError {
    // just an unknown error for now
    Unknown,
    EmptyPassword,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordEntry {
    name: String,
    username: String,
    password: String,
}

pub struct PasswordEntryBuilder<'a> {
    name: Option<&'a str>,
    username: Option<&'a str>,
    method: GenerationMethod,
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

    pub(crate) fn password(&self) -> &String {
        &self.password
    }
}

impl<'a> PasswordEntryBuilder<'a> {
    pub fn new() -> Self {
        Self {
            name: None,
            username: None,
            method: GenerationMethod::Random(32),
        }
    }

    pub fn build(self) -> PasswordEntry {
        let generator = Generator::from(self.method);
        let password = generator.generate().unwrap();

        PasswordEntry {
            name: String::from(self.name.unwrap()),
            username: String::from(self.username.unwrap()),
            password,
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::PasswordEntryBuilder as Builder;

    #[test]
    fn random_entry() {
        let builder = Builder::new()
            .name("Github")
            .username("myemail@protonmail.com")
            .generation_method(GenerationMethod::Random(20));

        let entry = builder.build();
        println!("{:#?}", entry);
        assert_eq!(entry.name, "Github");
        assert_eq!(entry.username, "myemail@protonmail.com");
        assert_eq!(entry.password.len(), 20);
    }

    #[test]
    fn diceware_entry() {
        let builder = Builder::new()
            .name("Github")
            .username("myemail@protonmail.com")
            .generation_method(GenerationMethod::Diceware(String::from("res/diceware_wordlist.txt"),5));

        let entry = builder.build();
        println!("{:#?}", entry);
        assert_eq!(entry.name, "Github");
        assert_eq!(entry.username, "myemail@protonmail.com");
    }
}
