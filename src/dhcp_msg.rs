use dhcproto::{v4, Encodable};
use log::error;

use crate::{mac::mac_str_to_u8_array, traits::Emitable, DhcpError, ErrorKind};

// RFC 2131
const CHADDR_LEN: usize = 16;
const SNAME_LEN: usize = 64;
const FILE_LEN: usize = 128;

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
const ARP_HW_TYPE_ETHERNET: u8 = 1;

#[derive(Debug, PartialEq, Clone, Default)]
pub(crate) struct Dhcp4Message {
    msg: v4::Message,
    mac: String,
    host_name: String,
}

impl Dhcp4Message {
    pub(crate) fn new() -> Self {
        let mut msg = v4::Message::default();
        msg.set_flags(v4::Flags::default());
        Dhcp4Message {
            msg,
            ..Default::default()
        }
    }

    pub(crate) fn set_host_name(
        mut self,
        host_name: &str,
    ) -> Result<Self, DhcpError> {
        if host_name.as_bytes().len() >= SNAME_LEN {
            let e = DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "WARN: Specified host_name '{}' exceeded the \
                    maximum length {}",
                    host_name,
                    SNAME_LEN - 1
                ),
            );
            error!("{}", e);
            Err(e)
        } else {
            self.host_name = host_name.to_string();
            self.msg.set_sname_str(host_name);
            Ok(self)
        }
    }

    pub(crate) fn set_hw_addr(
        mut self,
        hw_addr: &str,
    ) -> Result<Self, DhcpError> {
        let mut mac_bytes = mac_str_to_u8_array(hw_addr);
        if mac_bytes.len() >= CHADDR_LEN {
            let e = DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Specified hw_addr '{}' exceeded the maximum length {}",
                    hw_addr,
                    CHADDR_LEN - 1
                ),
            );
            error!("{}", e);
            Err(e)
        } else {
            self.mac = hw_addr.to_string();
            mac_bytes.resize(CHADDR_LEN, 0);
            self.msg.set_chaddr(&mac_bytes);
            Ok(self)
        }
    }

    pub(crate) fn client_identifier_use_mac(mut self) -> Self {
        let mut iaid = mac_str_to_u8_array(&self.mac);
        iaid.insert(0, ARP_HW_TYPE_ETHERNET);

        self.msg
            .opts_mut()
            .insert(v4::DhcpOption::ClientIdentifier(iaid));
        self
    }

    pub(crate) fn dhcp_discovery(mut self) -> Self {
        self.msg
            .opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
        self.msg
            .opts_mut()
            .insert(v4::DhcpOption::ParameterRequestList(vec![
                v4::OptionCode::SubnetMask,
                v4::OptionCode::Router,
                v4::OptionCode::DomainNameServer,
                v4::OptionCode::DomainName,
            ]));
        self
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, DhcpError> {
        let mut buf = Vec::new();
        let mut e = v4::Encoder::new(&mut buf);
        self.msg.encode(&mut e)?;
        Ok(buf)
    }
}
