use std::{env, path::Path};

pub mod cli;
pub mod error;
mod ffi;
pub mod generator;
pub mod password;
pub mod security;
pub mod vault;

// TODO: proper vault path
pub const DEFAULT_VAULT_PATH: &'static str = ".local/share/pwdeck/vault.pwd";

pub fn vault_path() -> String {
    if let Ok(path) = env::var("PWDECK_VAULT") {
        path
    } else {
        let user_home = env::var("HOME").unwrap();
        Path::new(&user_home)
            .join(DEFAULT_VAULT_PATH)
            .to_str()
            .unwrap()
            .into()
    }
}
