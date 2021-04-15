use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::{collections::HashMap, fs::File};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::Aes256Gcm;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    error::{PwdError, PwdResult},
    password::{Entry, PasswordError},
    security::{SecString, SecVec},
};

const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

const SCRYPT_LOGN: u8 = 12;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

#[derive(Serialize, Deserialize, Debug)]
/// The vault JSON schema
pub struct VaultSchema {
    pub(crate) passwords: HashMap<String, Vec<Entry>>,
}

impl Default for VaultSchema {
    /// Creates an empty schema
    fn default() -> Self {
        Self {
            passwords: HashMap::new(),
        }
    }
}

/// The Password vault
pub struct Vault {
    schema: VaultSchema,

    // not sure if the master password should be stored
    master_password: SecString,
    key: SecVec<u8>,
    salt: [u8; SALT_SIZE],

    scrypt_logn: u8,
    scrypt_r: u32,
    scrypt_p: u32,
}

/// Safe password vault storage
impl Vault {
    /// Create a new vault with the given master password
    pub fn new(master_password: &str) -> Self {
        let salt = {
            let mut salt = [0; SALT_SIZE];
            let mut rng = OsRng::default();
            rng.fill_bytes(&mut salt);
            salt
        };

        let scrypt_logn = SCRYPT_LOGN;
        let scrypt_r = SCRYPT_R;
        let scrypt_p = SCRYPT_P;

        // already tested params, should not be a problem
        let scrypt_params = scrypt::Params::new(scrypt_logn, scrypt_r, scrypt_p).unwrap();

        let mut key = vec![0; KEY_SIZE];
        // the params and the key length are right, so this will not panic
        scrypt::scrypt(master_password.as_bytes(), &salt, &scrypt_params, &mut key).unwrap();

        Self {
            schema: VaultSchema::default(),

            master_password: master_password.into(),
            key: key.into(),
            salt,

            scrypt_logn,
            scrypt_r,
            scrypt_p,
        }
    }

    /// Try to get the vault from a given file
    pub fn from_file(vault_file: &mut File, master_password: &str) -> PwdResult<Self> {
        // read the file and write its content into a `Vec`
        let mut buffer = Vec::new();
        vault_file.read_to_end(&mut buffer)?;

        // create the file reader
        let mut reader = Cursor::new(buffer);

        // read the metadata from the file
        let metadata = match Metadata::read(&mut reader) {
            Ok(metadata) => metadata,
            Err(error) => return Err(PwdError::from(error)),
        };

        // read the rest of the file
        let encrypted_schema = {
            let mut schema = Vec::new();
            reader.read_to_end(&mut schema)?;
            schema
        };

        // generate the key
        let mut key = vec![0; KEY_SIZE];
        // the key lenght is ok, should not panic
        scrypt::scrypt(
            master_password.as_bytes(),
            &metadata.salt,
            &metadata.scrypt.into(),
            &mut key,
        )
        .unwrap();

        let cipher = Aes256Gcm::new((*key).into());
        let json_schema = cipher
            .decrypt(&metadata.nonce.into(), encrypted_schema.as_ref())
            .unwrap_or_else(|_error| {
                panic!("Authentication failed");
            });

        let schema: VaultSchema = {
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

            master_password: master_password.into(),
            key: key.into(),
            salt: metadata.salt,

            scrypt_logn: metadata.scrypt.logn,
            scrypt_r: metadata.scrypt.r,
            scrypt_p: metadata.scrypt.p,
        };

        Ok(vault)
    }

    /// Add a new password to the vault
    pub fn insert_entry(&mut self, group: &str, entry: Entry) -> Result<(), PasswordError> {
        if entry.password().len() == 0 {
            return Err(PasswordError::EmptyPassword);
        }

        if let Some(group_entries) = self.schema.passwords.get_mut(group) {
            group_entries.push(entry);
        } else {
            // the key doesn't exists so its safe to just unwrap
            self.schema
                .passwords
                .insert(String::from(group), vec![entry]);
        }

        Ok(())
    }

    /// Sync the passwords with the vault file
    pub fn sync(&self, vault_file: &mut File) -> io::Result<()> {
        // create the aes cipher
        let key: &[u8] = &self.key;
        let cipher = Aes256Gcm::new(key.into());

        // generate a random nonce
        let nonce = {
            let mut nonce = [0; NONCE_SIZE];
            let mut rng = OsRng::default();
            rng.fill_bytes(&mut nonce);
            nonce
        };

        let schema = serde_json::to_string(&self.schema)?;
        // encrypt the schema
        let schema = cipher
            .encrypt(&nonce.into(), schema.as_ref())
            .unwrap_or_else(|error| {
                panic!("Encryption error: {}", error.to_string());
            });

        // write the metadata
        let mut writer = Cursor::new(Vec::new());
        self.metadata(nonce).write(&mut writer)?;
        // write the encrypted schema
        writer.write_all(&schema)?;

        // write the buffer content to the vault file
        // a bit more safe than writing directly into
        // the file
        vault_file.write_all(writer.get_ref())?;

        Ok(())
    }

    /// Return the vault's metadata
    fn metadata(&self, nonce: [u8; NONCE_SIZE]) -> Metadata {
        Metadata {
            scrypt: ScryptMetadata {
                logn: self.scrypt_logn,
                r: self.scrypt_r,
                p: self.scrypt_p,
            },
            nonce,
            salt: self.salt,
        }
    }

    /// Schema getter
    pub fn schema(&self) -> &VaultSchema {
        &self.schema
    }
}

// Metadata about the vault file
struct Metadata {
    scrypt: ScryptMetadata,
    nonce: [u8; NONCE_SIZE],
    salt: [u8; SALT_SIZE],
}

impl Metadata {
    fn read<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        // rewind the reader
        reader.seek(SeekFrom::Start(0))?;

        let scrypt_metadata = ScryptMetadata::read(reader)?;

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

        Ok(Self {
            scrypt: scrypt_metadata,
            nonce,
            salt,
        })
    }

    /// Write the metadata to the writer buffer.
    /// This includes the salt and other encryption
    /// informations such as the scrypt params used.
    fn write<W: Write + Seek>(self, writer: &mut W) -> io::Result<()> {
        // rewind
        writer.seek(SeekFrom::Start(0))?;

        writer.write_u8(self.scrypt.logn)?;
        writer.write_u32::<LittleEndian>(self.scrypt.r)?;
        writer.write_u32::<LittleEndian>(self.scrypt.p)?;

        writer.write_all(&self.nonce)?;
        writer.write_all(&self.salt)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ScryptMetadata {
    logn: u8,
    r: u32,
    p: u32,
}

impl ScryptMetadata {
    fn read<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        let logn = reader.read_u8()?;
        let r = reader.read_u32::<LittleEndian>()?;
        let p = reader.read_u32::<LittleEndian>()?;

        Ok(Self { logn, r, p })
    }
}

impl Into<scrypt::Params> for ScryptMetadata {
    fn into(self) -> scrypt::Params {
        scrypt::Params::new(self.logn, self.r, self.p)
            .unwrap_or_else(|error| panic!("invalid scrypt params: {}", error))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use super::*;
    use crate::password::*;

    const VAULT_PASSWD: &'static str = "123";
    const VAULT_PATH: &'static str = "target/debug.deck";

    fn test_vault() -> Vault {
        let mut test_entries = HashMap::new();

        test_entries.insert(
            "Reddit",
            vec![Entry::new("user1", "321foo"), Entry::new("user2", "123bar")],
        );
        test_entries.insert("Github", vec![Entry::new("foo@email.com", "baz")]);
        test_entries.insert(
            "Google",
            vec![
                Entry::new("main", "password"),
                Entry::new("secondary", "password"),
            ],
        );

        let mut vault = Vault::new(VAULT_PASSWD);

        for (group, entries) in test_entries.iter() {
            for entry in entries.iter() {
                vault.insert_entry(group, entry.clone()).unwrap();
            }
        }

        vault
    }

    #[test]
    fn insert_entry() {
        let vault = test_vault();

        println!("{:#?}", vault.schema);
        assert_eq!(vault.schema.passwords.len(), 3);
    }

    #[test]
    fn empty_password() {
        let mut vault = Vault::new(VAULT_PASSWD);
        let entry = Entry::new("test", "");

        assert!(vault.insert_entry("Test", entry).is_err());
    }

    #[test]
    fn sync_file() {
        let vault = test_vault();

        // open write
        let mut pwdeck_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(VAULT_PATH)
            .unwrap();

        assert!(vault.sync(&mut pwdeck_file).is_ok());
    }

    #[test]
    fn retrieve_vault() {
        {
            let vault = test_vault();

            // open write
            let mut pwdeck_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(VAULT_PATH)
                .unwrap();

            vault.sync(&mut pwdeck_file).unwrap();
        }

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
