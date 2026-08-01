"""Classifies an IPv4 address for two distinct, unrelated purposes:

- is_real_unicast_ip: is this even a plausible *device* address at all --
  used to keep 0.0.0.0 (pre-lease DHCP), the limited broadcast
  255.255.255.255, and multicast groups (224.0.0.0/4, e.g. mDNS's
  224.0.0.251 or SSDP's 239.255.255.250) from ever becoming inventory
  "devices" in the first place. These addresses aren't a host, on any
  network, so no capture context can make them one.

- is_lan_ip: is this address on the local/private network the sensor is
  actually deployed in, as opposed to some host out on the public
  internet the LAN merely talked to. A public IP is still a legitimate
  flow/vulnerability endpoint (the LAN device that reached it is real,
  and that conversation matters) -- it just isn't itself an asset this
  deployment should list as inventory.
"""

import ipaddress


def is_real_unicast_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    if ip == "255.255.255.255":
        return False
    return True


def is_lan_ip(ip: str | None) -> bool:
    """None (no IP -- e.g. a CDP/LLDP-only switch, identified by MAC alone)
    counts as LAN: it's still a real, local asset, just without an IP."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_link_local or addr.is_loopback
