#[derive(Debug, PartialEq, Clone)]
pub enum ErrorKind {
    InvalidArgument,
    Bug,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DhcpError {
    kind: ErrorKind,
    msg: String,
}

impl DhcpError {
    pub fn new(kind: ErrorKind, msg: String) -> Self {
        Self {
            kind: kind,
            msg: msg,
        }
    }
}
