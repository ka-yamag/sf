use std::fmt::{Debug, Formatter};
use std::fmt::Error as FmtError;
use std::io::Error as IoError;
use block_modes::InvalidKeyIvLength;
use std::sync::{MutexGuard, PoisonError};

// #[derive(PartialEq)]
pub struct SfError {
    pub message: String,
    pub stderr: Option<String>,
    pub stdout: Option<String>,
}

pub type SfResult = Result<(), SfError>;

impl SfError {
    pub fn new(message: String) -> SfError {
        SfError {
            message: message,
            stderr: None,
            stdout: None,
        }
    }
}

impl Debug for SfError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{:?}", self.message)
    }
}

impl From<IoError> for SfError {
    fn from(err: IoError) -> Self {
        SfError::new(format!("{}", err))
    }
}

impl From<InvalidKeyIvLength> for SfError {
    fn from(err: InvalidKeyIvLength) -> Self {
        SfError::new(format!("{}", err))
    }
}

impl From<PoisonError<MutexGuard<'_, &Vec<String>>>> for SfError {
    fn from(err: PoisonError<MutexGuard<'_, &Vec<String>>>) -> Self {
        SfError::new(format!("{}", err))
    }
}
