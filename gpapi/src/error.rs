use std::error::Error as StdError;
use std::fmt;

pub enum ErrorKind {
    FileExists,
    Other,
}

pub trait Error {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    } 
}

impl Error for dyn StdError {}

#[derive(Debug, Clone)]
pub struct FileExistsError;

impl StdError for FileExistsError {}
impl Error for FileExistsError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::FileExists
    }
}

impl fmt::Display for FileExistsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File already exists")
    }
}
