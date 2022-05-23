use std::error::Error as StdError;
use std::fmt;
use std::io::Error as IOError;

use protobuf::error::ProtobufError;
use tokio_dl_stream_to_disk::error::Error as TDSTDError;
use tokio_dl_stream_to_disk::error::ErrorKind as TDSTDErrorKind;

#[derive(Debug)]
pub enum ErrorKind {
    FileExists,
    DirectoryExists,
    DirectoryMissing,
    InvalidApp,
    SecurityCheck,
    EncryptLogin,
    PermissionDenied,
    IO(IOError),
    Str(String),
    Protobuf(ProtobufError),
    Other(Box<dyn StdError>),
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(k: ErrorKind) -> Error {
        Error { kind: k }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<IOError> for Error {
    fn from(err: IOError) -> Error {
        Error {
            kind: ErrorKind::IO(err),
        }
    }
}

impl From<Box<dyn StdError>> for Error {
    fn from(err: Box<dyn StdError>) -> Error {
        Error {
            kind: ErrorKind::Other(err),
        }
    }
}

impl From<TDSTDError> for Error {
    fn from(err: TDSTDError) -> Error {
        match err.kind() {
            TDSTDErrorKind::FileExists => Error {
                kind: ErrorKind::FileExists,
            },
            TDSTDErrorKind::DirectoryMissing => Error {
                kind: ErrorKind::DirectoryMissing,
            },
            TDSTDErrorKind::PermissionDenied => Error {
                kind: ErrorKind::PermissionDenied,
            },
            TDSTDErrorKind::IO(_) => {
                let err = err.into_inner_io().unwrap();
                Error {
                    kind: ErrorKind::IO(err),
                }
            }
            TDSTDErrorKind::Other(_) => {
                let err = err.into_inner_other().unwrap();
                Error {
                    kind: ErrorKind::Other(err),
                }
            }
        }
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error {
            kind: ErrorKind::Str(err.to_string()),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error {
            kind: ErrorKind::Str(err),
        }
    }
}

impl From<ProtobufError> for Error {
    fn from(err: ProtobufError) -> Error {
        Error {
            kind: ErrorKind::Protobuf(err),
        }
    }
}

impl StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind() {
            ErrorKind::FileExists => write!(f, "File already exists"),
            ErrorKind::InvalidApp => write!(f, "Invalid app response"),
            ErrorKind::DirectoryExists => write!(f, "Directory already exists"),
            ErrorKind::DirectoryMissing => write!(f, "Destination path provided is not a valid directory"),
            ErrorKind::SecurityCheck => write!(f, "Security check is needed, try to visit https://accounts.google.com/b/0/DisplayUnlockCaptcha to unlock, or setup an app-specific password"),
            ErrorKind::EncryptLogin => write!(f, "Error encrypting login information: login + password combination is too long. Please use a shorter or app-specific password"),
            ErrorKind::PermissionDenied => write!(f, "Cannot create file: permission denied"),
            ErrorKind::IO(err) => err.fmt(f),
            ErrorKind::Str(err) => err.fmt(f),
            ErrorKind::Protobuf(err) => err.fmt(f),
            ErrorKind::Other(err) => err.fmt(f),
        }
    }
}
