use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::Aes256Gcm;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::password::{Entry, PasswordError};

const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Serialize, Deserialize, Debug)]
/// The `pwdeck` file JSON Schema
pub struct Schema {
    pub(crate) passwords: Vec<Entry>,
}

impl Default for Schema {
    /// Creates an empty schema
    fn default() -> Self {
        Self {
            passwords: Vec::new(),
        }
    }
}

#[allow(dead_code)]
/// The Password Vault
pub struct Vault {
    schema: Schema,
    // not sure if the master password should be stored
    master_password: String,
    key: Box<[u8; KEY_SIZE]>,
    salt: [u8; SALT_SIZE],

    scrypt_logn: u8,
    scrypt_r: u32,
    scrypt_p: u32,
}

impl Vault {
    /// Creates a new password `Vault`
    pub fn new(master_password: &str) -> Self {
        let salt = {
            let mut salt = [0; SALT_SIZE];
            let mut rng = OsRng::default();
            rng.fill_bytes(&mut salt);
            salt
        };

        let scrypt_logn = 11;
        let scrypt_r = 8;
        let scrypt_p = 1;

        // already tested params, should not be a problem
        let scrypt_params = scrypt::Params::new(scrypt_logn, scrypt_r, scrypt_p).unwrap();

        let mut key = [0; KEY_SIZE];
        // the params and the key length are right, so this will not panic
        scrypt::scrypt(master_password.as_bytes(), &salt, &scrypt_params, &mut key).unwrap();

        Self {
            schema: Schema::default(),
            master_password: String::from(master_password),
            key: Box::new(key),
            salt,

            scrypt_logn,
            scrypt_r,
            scrypt_p,
        }
    }

    /// Try to get the `Vault` from a given file
    pub fn from_file(vault_file: &mut File, master_password: &str) -> io::Result<Self> {
        let mut buffer = Vec::new();
        vault_file.read_to_end(&mut buffer)?;

        let mut reader = Cursor::new(buffer);

        let mut scrypt_metadata = [0; 3];
        reader.read_exact(&mut scrypt_metadata)?;

        let scrypt_logn = scrypt_metadata[0];
        let scrypt_r = scrypt_metadata[1];
        let scrypt_p = scrypt_metadata[2];

        // TODO: error handling
        let scrypt_params =
            scrypt::Params::new(scrypt_logn, u32::from(scrypt_r), u32::from(scrypt_p))
                .unwrap_or_else(|error| panic!("Scrypt error: {}", error.to_string()));

        let nonce = {
            let mut nonce = [0; NONCE_SIZE];
            reader.read_exact(&mut nonce)?;
            nonce
        };

        let salt = {
            let mut salt = [0; SALT_SIZE];
            reader.read_exact(&mut salt)?;
            salt
        };

        let encrypted_schema = {
            let mut schema = Vec::new();
            reader.read_to_end(&mut schema)?;
            schema
        };

        let mut key = [0; KEY_SIZE];
        // the key lenght is ok, should not panic
        scrypt::scrypt(master_password.as_bytes(), &salt, &scrypt_params, &mut key).unwrap();

        let cipher = Aes256Gcm::new(key.as_ref().into());
        let json_schema = cipher
            .decrypt(&nonce.into(), encrypted_schema.as_ref())
            .unwrap_or_else(|_error| {
                panic!("Authentication failed");
            });

        let schema: Schema = {
            let encoded_schema = String::from_utf8_lossy(&json_schema);
            match serde_json::from_str(&encoded_schema) {
                Ok(schema) => schema,
                Err(error) => {
                    panic!("Invalid json file: {}", error.to_string())
                }
            }
        };

        let vault = Self {
            schema,
            master_password: String::from(master_password),
            key: Box::new(key),
            salt,

            scrypt_logn,
            scrypt_r: u32::from(scrypt_r),
            scrypt_p: u32::from(scrypt_p),
        };

        Ok(vault)
    }

    /// Add a new password to the vault
    pub fn add_password(&mut self, entry: Entry) -> Result<(), PasswordError> {
        if entry.password().len() == 0 {
            return Err(PasswordError::EmptyPassword);
        }

        self.schema.passwords.push(entry);

        Ok(())
    }

    /// Sync the passwords with the vault file
    pub fn sync(&self, vault_file: &mut File) -> io::Result<()> {
        let schema = serde_json::to_string(&self.schema)?;

        // create the aes cipher
        let key = *self.key;
        let cipher = Aes256Gcm::new(key.as_ref().into());

        // generate a random nonce
        let nonce = {
            let mut nonce = [0; NONCE_SIZE];
            let mut rng = OsRng::default();
            rng.fill_bytes(&mut nonce);
            nonce
        };

        // encrypt the password
        let schema = cipher
            .encrypt(&nonce.into(), schema.as_ref())
            .unwrap_or_else(|error| {
                panic!("Encryption error: {}", error.to_string());
            });

        // write the vault metadata
        self.write_metadata(vault_file, nonce)?;
        // write the encrypted schema
        vault_file.write_all(&schema.as_ref())?;

        Ok(())
    }

    /// Write the vault metadata to the file.
    /// This includes the salt and other encryption
    /// informations such as the scrypt params used.
    /// NOTE: this will erase all the file content
    pub fn write_metadata(&self, file: &mut File, nonce: [u8; NONCE_SIZE]) -> io::Result<()> {
        // go to the start of the file
        file.seek(SeekFrom::Start(0))?;
        // make sure to erase the content
        file.set_len(0)?;

        let scrypt_metadata = [self.scrypt_logn, self.scrypt_r as u8, self.scrypt_p as u8];

        file.write_all(&scrypt_metadata)?;
        file.write_all(&nonce)?;
        file.write_all(&self.salt)?;

        Ok(())
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use super::*;
    use crate::password::*;

    const VAULT_PASSWD: &'static str = "SuPeRsEcReTkEy";
    const VAULT_PATH: &'static str = "target/debug.deck";

    #[test]
    fn add_password() {
        let diceware_wordlist = "res/diceware_wordlist.txt".to_string();

        let p1 = EntryBuilder::new()
            .name("Github")
            .username("mygitusername")
            .generation_method(GenerationMethod::Random(25))
            .build()
            .unwrap();
        let p2 = EntryBuilder::new()
            .name("Reddit")
            .username("myemail@mail.com")
            .generation_method(GenerationMethod::Diceware(diceware_wordlist, 4))
            .build()
            .unwrap();
        let p3 = EntryBuilder::new()
            .name("Discord")
            .username("mydiscordusername")
            .build()
            .unwrap();

        let mut vault = Vault::new(VAULT_PASSWD);

        vault.add_password(p1).unwrap();
        vault.add_password(p2).unwrap();
        vault.add_password(p3).unwrap();

        println!("{:#?}", vault.schema);
        assert_eq!(vault.schema.passwords.len(), 3);
    }

    #[test]
    fn sync_file() {
        let diceware_wordlist = "res/diceware_wordlist.txt".to_string();

        let p1 = EntryBuilder::new()
            .name("Github")
            .username("mygitusername")
            .generation_method(GenerationMethod::Random(25))
            .build()
            .unwrap();
        let p2 = EntryBuilder::new()
            .name("Reddit")
            .username("myemail@mail.com")
            .generation_method(GenerationMethod::Diceware(diceware_wordlist, 4))
            .build()
            .unwrap();
        let p3 = EntryBuilder::new()
            .name("Discord")
            .username("mydiscordusername")
            .build()
            .unwrap();

        let mut vault = Vault::new(VAULT_PASSWD);

        vault.add_password(p1).unwrap();
        vault.add_password(p2).unwrap();
        vault.add_password(p3).unwrap();

        // open write
        let mut pwdeck_file = OpenOptions::new().write(true).create(true).open(VAULT_PATH).unwrap();
        assert!(vault.sync(&mut pwdeck_file).is_ok());
    }

    #[test]
    fn retrieve_vault() {
        // open read only
        let mut pwdeck_file = File::open(VAULT_PATH).unwrap();

        let vault = Vault::from_file(&mut pwdeck_file, VAULT_PASSWD);
        assert!(vault.is_ok());
        let vault = vault.unwrap();

        println!("{:#?}", vault.schema);
        assert_eq!(vault.schema.passwords.len(), 3);
    }

    #[test]
    #[should_panic]
    fn retrieve_wrong_password() {
        // open read only
        let mut pwdeck_file = File::open(VAULT_PATH).unwrap();

        let _ = Vault::from_file(&mut pwdeck_file, "Wrong password").unwrap();
    }
}
