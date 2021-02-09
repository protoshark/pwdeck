use std::io;

pub type PwdResult<T> = Result<T, PwdError>;

#[derive(Debug)]
pub enum PwdError {
    AuthenticationFailed,
    InvalidVaultFile,
    InvalidPassword,

    IO(io::Error)
}

impl From<io::Error> for PwdError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}
