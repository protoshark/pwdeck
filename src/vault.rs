use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::{fs::File, slice};

use serde::{Deserialize, Serialize};

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::password::{PasswordEntry, PasswordError};

const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

fn scrypt_params() -> scrypt::Params {
    scrypt::Params::new(11, 8, 1).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Schema {
    passwords: Vec<PasswordEntry>,
}

impl Schema {
    pub fn new() -> Self {
        Self {
            passwords: Vec::new(),
        }
    }
}

pub struct Vault {
    schema: Schema,
    master_password: String,
    key: Box<[u8; KEY_SIZE]>,
    salt: [u8; SALT_SIZE],

    scrypt_logn: u8,
    scrypt_r: u32,
    scrypt_p: u32,
}

impl Vault {
    /// creates a new password vault
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

        let scrypt_params = {
            let params = scrypt::Params::new(scrypt_logn, scrypt_r, scrypt_p);
            debug_assert!(params.is_ok());
            params.unwrap()
        };

        let mut key = [0; 32];
        scrypt::scrypt(master_password.as_bytes(), &salt, &scrypt_params, &mut key).unwrap();

        Self {
            schema: Schema::new(),
            master_password: String::from(master_password),
            key: Box::new(key),
            salt,

            scrypt_logn,
            scrypt_r,
            scrypt_p,
        }
    }

    /// try to get the vault from the given filie
    pub fn from_file(vault_file: &mut File, master_password: &str) -> io::Result<Self> {
        // FIXME
        let vault = Self::new(master_password);

        Ok(vault)
    }

    /// add a new password to the vault
    pub fn add_password(&mut self, entry: PasswordEntry) -> Result<(), PasswordError> {
        if entry.password().len() == 0 {
            return Err(PasswordError::EmptyPassword);
        }

        self.schema.passwords.push(entry);

        Ok(())
    }

    /// sync the passwords with the vault file
    pub fn sync(&self, vault_file: &mut File) -> io::Result<()> {
        let schema = serde_json::to_string(&self.schema)?;

        // transform the key into an generic array
        let key = GenericArray::from_slice(self.key.as_ref());
        // create the aes cipher
        let cipher = Aes256Gcm::new(&key);

        // generate a random nonce
        let nonce = {
            let mut nonce = [0; NONCE_SIZE];
            let mut rng = OsRng::default();
            rng.fill_bytes(&mut nonce);
            nonce
        };
        // encrypt the passwords
        // TODO: error handling
        let schema = cipher.encrypt(&nonce.into(), schema.as_ref()).unwrap();

        // write the vault metadata
        self.write_metadata(vault_file, nonce)?;
        // write the encrypted schema
        vault_file.write_all(&schema.as_ref())?;

        Ok(())
    }

    /// write the vault metadata to the file
    /// this includes the salt and other encryption informations such as the scrypt params used
    /// NOTE: this will erase all the file content
    pub fn write_metadata(&self, file: &mut File, nonce: [u8; NONCE_SIZE]) -> io::Result<()> {
        // go to the start of the file
        file.seek(SeekFrom::Start(0))?;
        // make sure to erase the content
        file.set_len(0)?;

        let mut scrypt_metadata = vec![self.scrypt_logn];

        scrypt_metadata.write_all(unsafe {
            let data = [self.scrypt_r, self.scrypt_p];
            let ptr = data.as_ptr() as *const u8;
            std::slice::from_raw_parts(ptr, 2 * std::mem::size_of::<u32>())
        })?;

        file.write_all(&scrypt_metadata)?;
        file.write_all(&nonce)?;
        file.write_all(&self.salt)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use super::*;
    use crate::password::*;

    const VAULT_PASSWD: &'static str = "SuPeRsEcReTkEy";
    const VAULT_PATH: &'static str = "res/debug.psm";

    #[test]
    #[ignore]
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

        // open write
        let mut vault_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(VAULT_PATH)
            .unwrap();
        let mut vault = Vault::new(VAULT_PASSWD);

        vault.add_password(p1).unwrap();
        vault.add_password(p2).unwrap();
        vault.add_password(p3).unwrap();

        assert!(vault.sync(&mut vault_file).is_ok());
    }

    #[test]
    fn retrieve_vault() {
        // open read only
        let mut vault_file = File::open(VAULT_PATH).unwrap();

        let vault = Vault::from_file(&mut vault_file, VAULT_PASSWD);
        assert!(vault.is_ok());
        let vault = vault.unwrap();

        assert_eq!(vault.schema.passwords.len(), 3);
        // TODO: check if the entries match
    }
}
