use std::error::Error as StdError;
use std::io::Error as IOError;
use std::fmt;

use protobuf::error::ProtobufError;

#[derive(Debug)]
pub enum ErrorKind {
    FileExists,
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
        Error {
            kind: k,
        }
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
        write!(f, "File already exists")
    }
}
