use std::fs::File;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::password::{PasswordEntry, PasswordError};

#[derive(Serialize, Deserialize, Debug)]
pub struct Schema {
    passwords: Vec<PasswordEntry>,
}

pub struct Vault {
    schema: Schema,
}

impl Schema {
    pub fn new() -> Self {
        Self {
            passwords: Vec::new(),
        }
    }
}

impl Vault {
    pub fn new() -> Self {

        Self {
            schema: Schema::new(),
        }
    }

    /// sync the passwords with the vault file
    pub fn sync(&self, vault_file: &mut File) -> io::Result<()> {
        let schema = serde_json::to_string(&self.schema)?;

        vault_file.write_all(&schema.as_ref())?;

        Ok(())
    }

    /// add a new password to the vault
    pub fn add_password(&mut self, entry: PasswordEntry) -> Result<(), PasswordError> {
        if entry.password().len() == 0 {
            return Err(PasswordError::EmptyPassword);
        }

        self.schema.passwords.push(entry);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use super::*;
    use crate::password::*;

    #[test]
    fn add_password() {
        let diceware_wordlist = "res/diceware_wordlist.txt".to_string();

        let p1 = PasswordEntryBuilder::new()
            .name("Github")
            .username("mygitusername")
            .generation_method(GenerationMethod::Random(25))
            .build();
        let p2 = PasswordEntryBuilder::new()
            .name("Reddit")
            .username("myemail@mail.com")
            .generation_method(GenerationMethod::Diceware(diceware_wordlist, 4))
            .build();
        let p3 = PasswordEntryBuilder::new()
            .name("Discord")
            .username("mydiscordusername")
            .build();



        let mut vault = Vault::new();

        vault.add_password(p1).unwrap();
        vault.add_password(p2).unwrap();
        vault.add_password(p3).unwrap();

        println!("{:#?}", vault.schema);
        assert_eq!(vault.schema.passwords.len(), 3);
    }

    #[test]
    fn sync_file() {
        let diceware_wordlist = "res/diceware_wordlist.txt".to_string();

        let p1 = PasswordEntryBuilder::new()
            .name("Github")
            .username("mygitusername")
            .generation_method(GenerationMethod::Random(25))
            .build();
        let p2 = PasswordEntryBuilder::new()
            .name("Reddit")
            .username("myemail@mail.com")
            .generation_method(GenerationMethod::Diceware(diceware_wordlist, 4))
            .build();
        let p3 = PasswordEntryBuilder::new()
            .name("Discord")
            .username("mydiscordusername")
            .build();

        let mut vault_file = OpenOptions::new().write(true).read(true).create(true).open("res/debug.psm").unwrap();
        let mut vault = Vault::new();

        vault.add_password(p1).unwrap();
        vault.add_password(p2).unwrap();
        vault.add_password(p3).unwrap();

        vault.sync(&mut vault_file).unwrap();
    }
}
