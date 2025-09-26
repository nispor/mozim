// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use dhcproto::{
    v6::{DhcpOption, OptionCode},
    Encodable,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct DhcpV6Options {
    data: HashMap<u16, Vec<Vec<u8>>>,
}

impl DhcpV6Options {
    pub(crate) fn new<'a, T>(opts: T) -> Self
    where
        T: Iterator<Item = &'a DhcpOption>,
    {
        let mut data: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        for opt in opts {
            if let Ok(raw) = opt.to_vec() {
                data.entry(get_opt_code(opt)).or_default().push(raw);
            }
        }
        Self { data }
    }

    pub(crate) fn get_data_raw(&self, code: u16) -> Option<&[Vec<u8>]> {
        self.data.get(&code).map(|v| v.as_slice())
    }
}

fn get_opt_code(opt: &DhcpOption) -> u16 {
    match opt {
        DhcpOption::ClientId(_) => OptionCode::ClientId,
        DhcpOption::ServerId(_) => OptionCode::ServerId,
        DhcpOption::IANA(_) => OptionCode::IANA,
        DhcpOption::IATA(_) => OptionCode::IATA,
        DhcpOption::IAAddr(_) => OptionCode::IAAddr,
        DhcpOption::ORO(_) => OptionCode::ORO,
        DhcpOption::Preference(_) => OptionCode::Preference,
        DhcpOption::ElapsedTime(_) => OptionCode::ElapsedTime,
        DhcpOption::RelayMsg(_) => OptionCode::RelayMsg,
        DhcpOption::Authentication(_) => OptionCode::Authentication,
        DhcpOption::ServerUnicast(_) => OptionCode::ServerUnicast,
        DhcpOption::StatusCode(_) => OptionCode::StatusCode,
        DhcpOption::RapidCommit => OptionCode::RapidCommit,
        DhcpOption::UserClass(_) => OptionCode::UserClass,
        DhcpOption::VendorClass(_) => OptionCode::VendorClass,
        DhcpOption::VendorOpts(_) => OptionCode::VendorOpts,
        DhcpOption::InterfaceId(_) => OptionCode::InterfaceId,
        DhcpOption::ReconfMsg(_) => OptionCode::ReconfMsg,
        DhcpOption::ReconfAccept => OptionCode::ReconfAccept,
        DhcpOption::DomainNameServers(_) => OptionCode::DomainNameServers,
        DhcpOption::DomainSearchList(_) => OptionCode::DomainSearchList,
        DhcpOption::IAPD(_) => OptionCode::IAPD,
        DhcpOption::IAPrefix(_) => OptionCode::IAPrefix,
        DhcpOption::InformationRefreshTime(_) => {
            OptionCode::InformationRefreshTime
        }
        DhcpOption::NtpServer(_) => OptionCode::NtpServer,
        DhcpOption::Unknown(u) => u.code(),
    }
    .into()
}
