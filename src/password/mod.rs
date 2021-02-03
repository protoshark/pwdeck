use serde::{Deserialize, Serialize};

pub mod generator;

pub use generator::{GenerationMethod, Generator};

#[derive(Debug)]
// maybe rename it?
pub enum PasswordError {
    Unknown,
    EmptyPassword,
    NoNameProvided,
    NoUsernameProvided,
}

// TODO: maybe move to vault module as a vault entry
#[derive(Serialize, Deserialize, Debug)]
/// Stores a password entry
pub struct Entry {
    name: String,
    username: String,
    password: String,
}

#[allow(dead_code)] // suppress warnings for now
impl Entry {
    /// Get the entry name
    pub(crate) fn name(&self) -> &String {
        &self.name
    }
    pub(crate) fn username(&self) -> &String {
        &self.username
    }
    /// Get the entry password
    pub(crate) fn password(&self) -> &String {
        &self.password
    }
}

/// Password Entry Builder
pub struct EntryBuilder<'a> {
    name: Option<&'a str>,
    username: Option<&'a str>,
    method: GenerationMethod,
}

impl<'a> EntryBuilder<'a> {
    pub fn new() -> Self {
        Self {
            name: None,
            username: None,
            method: GenerationMethod::Random(20),
        }
    }

    /// Build the entry
    pub fn build(self) -> Result<Entry, PasswordError> {
        let generator = Generator::from(self.method);
        let password = generator.generate().unwrap();

        let name = String::from(match self.name {
            Some(name) => name,
            None => return Err(PasswordError::NoNameProvided),
        });

        let username = String::from(match self.username {
            Some(username) => username,
            None => return Err(PasswordError::NoUsernameProvided),
        });

        Ok(Entry {
            name,
            username,
            password,
        })
    }

    /// Set the name of the entry
    pub fn name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }
    /// Set the username/email of the entry
    pub fn username(mut self, username: &'a str) -> Self {
        self.username = Some(username);
        self
    }
    /// Set the password's generation method
    pub fn generation_method(mut self, method: GenerationMethod) -> Self {
        self.method = method;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::EntryBuilder as Builder;
    use super::*;

    #[test]
    fn random_entry() {
        let entry = Builder::new()
            .name("Github")
            .username("myemail@mail.com")
            .build()
            .unwrap();

        println!("{:#?}", entry);
        assert_eq!(entry.name, "Github");
        assert_eq!(entry.username, "myemail@mail.com");

        // implicit generation method should be a random generation with size 20
        assert_eq!(entry.password.len(), 20);
    }

    #[test]
    fn diceware_entry() {
        let entry = Builder::new()
            .name("Github")
            .username("myemail@mail.com")
            .generation_method(GenerationMethod::Diceware(
                String::from("res/diceware_wordlist.txt"),
                5,
            ))
            .build()
            .unwrap();

        println!("{:#?}", entry);
        assert_eq!(entry.name, "Github");
        assert_eq!(entry.username, "myemail@mail.com");
    }
}
