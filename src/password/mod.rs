use serde::{Deserialize, Serialize};

pub use crate::generator::Generator;
use crate::security::SecString;

#[derive(Debug, PartialEq)]
// maybe rename it?
pub enum PasswordError {
    Unknown,
    EmptyPassword,
}

// TODO: maybe move to vault module as a vault entry
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
/// Stores a password entry
pub struct Entry {
    id: String,
    name: String,
    password: SecString,
}

#[allow(dead_code)] // suppress warnings for now
impl Entry {
    pub fn new(name: &str, password: &str) -> Self {
        let id = nanoid::nanoid!();

        let name = String::from(name);
        let password = SecString::from(password);

        Self {
            id,
            name,
            password,
        }
    }
    /// Get the entry id
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    /// Get the entry name
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    /// Get the entry password
    pub(crate) fn password(&self) -> &SecString {
        &self.password
    }
}
