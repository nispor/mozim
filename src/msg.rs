use std::net::Ipv4Addr;

use dhcproto::{v4, Decodable, Decoder, Encodable};

use crate::{
    mac::{
        mac_address_to_eth_mac_bytes, mac_str_to_u8_array,
        u8_array_to_mac_string,
    },
    DhcpError, DhcpV4Config, DhcpV4Lease, ErrorKind,
};

// RFC 2131
const CHADDR_LEN: usize = 16;

const BROADCAST_MAC_ADDRESS: &str = "ff:ff:ff:ff:ff:ff";
const DEFAULT_TTL: u8 = 128;

#[derive(Debug, PartialEq, Clone)]
pub enum DhcpV4MessageType {
    Discovery,
    Offer,
    Request,
    Ack,
    Nack,
    Decline,
    Release,
    Inform,
    Unknown,
}

impl Default for DhcpV4MessageType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct DhcpV4Message {
    pub msg_type: DhcpV4MessageType,
    pub lease: Option<DhcpV4Lease>,
    pub config: DhcpV4Config,
    srv_mac: String,
}

impl DhcpV4Message {
    pub fn new(config: &DhcpV4Config, msg_type: DhcpV4MessageType) -> Self {
        Self {
            msg_type,
            config: config.clone(),
            lease: None,
            srv_mac: "".into(),
        }
    }

    pub fn load_lease(&mut self, lease: DhcpV4Lease) -> &mut Self {
        self.lease = Some(lease);
        if self.msg_type == DhcpV4MessageType::Discovery {
            self.msg_type = DhcpV4MessageType::Request;
        }
        self
    }

    pub(crate) fn to_eth_pkg(&self) -> Result<Vec<u8>, DhcpError> {
        let mut dhcp_msg = v4::Message::default();
        dhcp_msg.set_flags(v4::Flags::default());

        if !self.config.host_name.as_str().is_empty() {
            dhcp_msg.set_sname_str(self.config.host_name.clone());
        }

        if !self.config.iface_mac.as_str().is_empty() {
            let mut mac_bytes =
                mac_str_to_u8_array(self.config.iface_mac.as_str());
            mac_bytes.resize(CHADDR_LEN, 0);
            dhcp_msg.set_chaddr(&mac_bytes);
        }

        if self.msg_type == DhcpV4MessageType::Discovery {
            dhcp_msg
                .opts_mut()
                .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
            dhcp_msg
                .opts_mut()
                .insert(v4::DhcpOption::ParameterRequestList(vec![
                    v4::OptionCode::Hostname,
                    v4::OptionCode::SubnetMask,
                    v4::OptionCode::Router,
                    v4::OptionCode::DomainNameServer,
                    v4::OptionCode::DomainName,
                    v4::OptionCode::InterfaceMtu,
                    v4::OptionCode::NTPServers,
                ]));
        } else if self.msg_type == DhcpV4MessageType::Request {
            todo!()
        } else {
            let e = DhcpError::new(
                ErrorKind::InvalidArgument,
                format!("Unsupported DHCP message type {:?}", self.msg_type),
            );
            log::error!("{}", e);
            return Err(e);
        }

        dhcp_msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(
            self.config.client_id.clone(),
        ));

        let mut dhcp_msg_buff = Vec::new();
        let mut e = v4::Encoder::new(&mut dhcp_msg_buff);
        dhcp_msg.encode(&mut e)?;
        gen_eth_pkg(
            &self.config.iface_mac,
            if self.srv_mac.is_empty() {
                BROADCAST_MAC_ADDRESS
            } else {
                self.srv_mac.as_str()
            },
            &Ipv4Addr::new(0, 0, 0, 0),
            &Ipv4Addr::new(255, 255, 255, 255),
            dhcproto::v4::CLIENT_PORT,
            dhcproto::v4::SERVER_PORT,
            &dhcp_msg_buff,
        )
    }
}

impl std::convert::TryFrom<&[u8]> for DhcpV4Message {
    type Error = DhcpError;
    fn try_from(eth_raw: &[u8]) -> Result<Self, Self::Error> {
        let pkg = match etherparse::SlicedPacket::from_ethernet(eth_raw) {
            Err(error) => {
                let e = DhcpError::new(
                    ErrorKind::InvalidDhcpServerReply,
                    format!(
                        "Failed to parse ethernet package to Dhcpv4Offer: {}",
                        error
                    ),
                );
                log::error!("{}", e);
                return Err(e);
            }
            Ok(v) => v,
        };
        let eth_hdr = if let Some(i) = &pkg.link {
            i.to_header()
        } else {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Got invalid ethernet header from Dhcpv4Offer: {:?}",
                    pkg
                ),
            );
            log::error!("{}", e);
            return Err(e);
        };
        let v4_dhcp_msg = v4::Message::decode(&mut Decoder::new(pkg.payload))
            .map_err(|decode_error| {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Failed to parse DHCP message from payload of pkg \
                        {:?}: {}",
                    pkg, decode_error
                ),
            );
            log::error!("{}", e);
            e
        })?;

        let msg_type = match v4_dhcp_msg.opts().get(v4::OptionCode::MessageType)
        {
            Some(v4::DhcpOption::MessageType(v4::MessageType::Offer)) => {
                DhcpV4MessageType::Offer
            }
            Some(t) => {
                log::debug!("Unknown dhcp message type {:?}", t);
                DhcpV4MessageType::Unknown
            }
            None => {
                log::debug!("Got no dhcp message type");
                DhcpV4MessageType::Unknown
            }
        };

        Ok(Self {
            srv_mac: u8_array_to_mac_string(&eth_hdr.source),
            lease: Some(DhcpV4Lease::try_from(&v4_dhcp_msg)?),
            msg_type,
            ..Default::default()
        })
    }
}

fn gen_eth_pkg(
    src_mac: &str,
    dst_mac: &str,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, DhcpError> {
    let src_mac = mac_address_to_eth_mac_bytes(src_mac)?;
    let dst_mac = mac_address_to_eth_mac_bytes(dst_mac)?;
    let builder = etherparse::PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip.octets(), dst_ip.octets(), DEFAULT_TTL)
        .udp(src_port, dst_port);

    let mut pkg = Vec::<u8>::with_capacity(builder.size(payload.len()));

    builder.write(&mut pkg, payload)?;

    Ok(pkg)
}
