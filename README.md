# Mozim -- DHCP Client Library

Still doing code sign, no real work this project can do yet.
Check again in 2022.

DONE:
 * raw socket with BPF applied and accepting all mac address.
 * DHCP discovery and request.
 * Renew, rebind.
 * DHCP IP apply via cli tool `mzc`.
 * Route
 * Timeout and retry

TODO:
 * Verify XID.
 * Handle vendor difference: https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues/848
 * Support multiple DHCP servers with `DHCPNAK` reply.
 * Support DHCPNAK

# Try out

```bash
# Below script will create veth eth1/eth1.ep.
# The `eth1.ep` is DHCP server interface running dnsmasq in `mozim` network
# namespace.
sudo ./utils/test_env_mozim &
cargo run
```
