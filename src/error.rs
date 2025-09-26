// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    Timeout,
    InvalidArgument,
    InvalidDhcpServerReply,
    IoError,
    NoLease,
    NotSupported,
    Bug,
    LeaseExpired,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DhcpError {
    kind: ErrorKind,
    msg: String,
}

impl DhcpError {
    pub fn new(kind: ErrorKind, msg: String) -> Self {
        Self { kind, msg }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn msg(&self) -> &str {
        self.msg.as_str()
    }

    pub fn context<T>(self, msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self {
            kind: self.kind,
            msg: format!("{} caused by {}", msg, self.msg),
        }
    }
}

impl std::error::Error for DhcpError {}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::fmt::Display for DhcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

impl From<std::io::Error> for DhcpError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Bug, format!("IO error: {e}"))
    }
}

impl From<std::ffi::NulError> for DhcpError {
    fn from(e: std::ffi::NulError) -> Self {
        Self::new(ErrorKind::Bug, format!("CString error: {e}"))
    }
}

impl From<dhcproto::v4::EncodeError> for DhcpError {
    fn from(e: dhcproto::v4::EncodeError) -> Self {
        Self::new(ErrorKind::Bug, format!("DHCP protocol error: {e}"))
    }
}

impl From<std::net::AddrParseError> for DhcpError {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::new(ErrorKind::Bug, format!("IPv4 address parse error: {e}"))
    }
}

impl From<rtnetlink::Error> for DhcpError {
    fn from(e: rtnetlink::Error) -> Self {
        Self::new(ErrorKind::IoError, format!("netlink error: {e}"))
    }
}
