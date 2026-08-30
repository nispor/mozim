- DHCPv6 domain names reject RFC 1035 compressed/pointer-style
  labels (RFC 1035 section 4.1.4); parsing returns
  `InvalidDhcpMessage` when the high two bits of a label length
  are set.
