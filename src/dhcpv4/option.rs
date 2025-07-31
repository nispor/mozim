// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::Ipv4Addr;

use dhcproto::{
    v4::{DhcpOption, OptionCode},
    Decodable, Encodable,
};

// Microsoft Classless Static Route Option, data format is identical to
// RFC 3442: Classless Static Route Option(121)
pub(crate) const V4_OPT_CODE_MS_CLASSLESS_STATIC_ROUTE: u8 = 249;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct DhcpV4Options {
    data: HashMap<u8, Vec<u8>>,
}

impl DhcpV4Options {
    pub(crate) fn new<'a, T>(opts: T) -> Self
    where
        T: Iterator<Item = (&'a OptionCode, &'a DhcpOption)>,
    {
        let mut data = HashMap::new();
        for (code, opt) in opts {
            if let Ok(raw) = opt.to_vec() {
                data.insert(u8::from(*code), raw);
            }
        }
        Self { data }
    }

    pub(crate) fn get_data_raw(&self, code: u8) -> Option<&[u8]> {
        self.data.get(&code).map(|v| v.as_slice())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DhcpV4ClasslessRoute {
    pub destination: Ipv4Addr,
    pub prefix_length: u8,
    pub router: Ipv4Addr,
}

impl DhcpV4ClasslessRoute {
    pub(crate) fn parse_raw(mut raw: Vec<u8>) -> Option<Vec<Self>> {
        if !raw.is_empty() {
            raw[0] = OptionCode::ClasslessStaticRoute.into();
            if let Ok(DhcpOption::ClasslessStaticRoute(v)) =
                DhcpOption::decode(&mut dhcproto::Decoder::new(raw.as_slice()))
            {
                return Some(Self::parse(&v));
            }
        }
        None
    }

    pub(crate) fn parse(rts: &[(ipnet::Ipv4Net, Ipv4Addr)]) -> Vec<Self> {
        let mut ret = Vec::new();
        for (dst, router) in rts {
            ret.push(Self {
                destination: dst.addr(),
                prefix_length: dst.prefix_len(),
                router: *router,
            });
        }
        ret
    }
}
