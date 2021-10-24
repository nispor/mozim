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
    pub fn invalid_argument(msg: String) -> Self {
        Self {
            kind: ErrorKind::InvalidArgument,
            msg: msg,
        }
    }
    pub fn bug(msg: String) -> Self {
        Self {
            kind: ErrorKind::Bug,
            msg: msg,
        }
    }
}
