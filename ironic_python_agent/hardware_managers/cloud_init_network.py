# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 s3rj1k
#
# Portions derived from cloud-init:
# Copyright (C) 2012 Canonical Ltd.
# Copyright (C) 2012 Hewlett-Packard Development Company, L.P.
# Copyright (C) 2012 Yahoo! Inc.

"""Cloud-init network configuration utilities.

This module provides utilities for converting OpenStack network_data.json
format to cloud-init network config v1 format. It's derived from cloud-init's
openstack.py helper module with custom extensions for linux_bridge support.
"""

import copy
import glob
import logging
import os

LOG = logging.getLogger(__name__)

# Link types that represent physical interfaces
KNOWN_PHYSICAL_TYPES = (
    "ethernet",
    "ovs",
    "phy",
    "tap",
    "vhostuser",
    "vif",
)

# Guest-side Linux bridge types (distinct from hypervisor bridges)
KNOWN_BRIDGE_TYPES = ("linux_bridge",)


def convert_net_json(network_json=None, known_macs=None):
    """Convert OpenStack network_data.json to cloud-init v1 format.

    :param network_json: OpenStack network_data.json dictionary
    :param known_macs: Optional dict mapping MAC addresses to interface names
    :returns: Cloud-init network config v1 format dictionary
    """
    if network_json is None:
        return None

    # Valid cloud-init keys for filtering OpenStack data
    valid_keys = {
        "physical": [
            "name",
            "type",
            "mac_address",
            "subnets",
            "params",
            "mtu",
        ],
        "subnet": [
            "type",
            "address",
            "netmask",
            "broadcast",
            "metric",
            "gateway",
            "pointopoint",
            "scope",
            "dns_nameservers",
            "dns_search",
        ],
        "routes": ["network", "destination", "netmask", "gateway", "metric"],
    }

    links = network_json.get("links", [])
    networks = network_json.get("networks", [])
    services = network_json.get("services", [])

    link_updates = []
    link_id_info = {}
    bond_name_fmt = "bond%d"
    bond_number = 0
    config = []
    for link in links:
        subnets = []
        cfg = dict(
            (k, v) for k, v in link.items() if k in valid_keys["physical"]
        )
        # Use 'name' if present, otherwise use 'id' (may be auto-generated)
        if "name" in link:
            cfg["name"] = link["name"]

        link_mac_addr = None
        if link.get("ethernet_mac_address"):
            link_mac_addr = link.get("ethernet_mac_address").lower()
            link_id_info[link["id"]] = link_mac_addr

        curinfo = {
            "name": cfg.get("name"),
            "mac": link_mac_addr,
            "id": link["id"],
            "type": link["type"],
        }

        for network in [n for n in networks if n["link"] == link["id"]]:
            subnet = dict(
                (k, v) for k, v in network.items() if k in valid_keys["subnet"]
            )

            # Filter routes to include only valid cloud-init keys
            routes = [
                dict(
                    (k, v)
                    for k, v in route.items()
                    if k in valid_keys["routes"]
                )
                for route in network.get("routes", [])
            ]

            if routes:
                subnet.update({"routes": routes})

            if network["type"] == "ipv4_dhcp":
                subnet.update({"type": "dhcp4"})
            elif network["type"] == "ipv6_dhcp":
                subnet.update({"type": "dhcp6"})
            elif network["type"] in [
                "ipv6_slaac",
                "ipv6_dhcpv6-stateless",
                "ipv6_dhcpv6-stateful",
            ]:
                subnet.update({"type": network["type"]})
            elif network["type"] in ["ipv4", "static"]:
                subnet.update(
                    {
                        "type": "static",
                        "address": network.get("ip_address"),
                    }
                )
            elif network["type"] in ["ipv6", "static6"]:
                cfg.update({"accept-ra": False})
                subnet.update(
                    {
                        "type": "static6",
                        "address": network.get("ip_address"),
                    }
                )

            # Collect DNS servers from routes and network services
            dns_nameservers = [
                service["address"]
                for route in network.get("routes", [])
                for service in route.get("services", [])
                if service.get("type") == "dns"
            ]
            for service in network.get("services", []):
                if service.get("type") != "dns":
                    continue
                if service["address"] in dns_nameservers:
                    continue
                dns_nameservers.append(service["address"])
            if dns_nameservers:
                subnet["dns_nameservers"] = dns_nameservers

            # Enable accept_ra for stateful and legacy ipv6_dhcp types
            if network["type"] in ["ipv6_dhcpv6-stateful", "ipv6_dhcp"]:
                cfg.update({"accept-ra": True})

            if network["type"] == "ipv4":
                subnet["ipv4"] = True
            if network["type"] == "ipv6":
                subnet["ipv6"] = True
            subnets.append(subnet)
        cfg.update({"subnets": subnets})
        if link["type"] in ["bond"]:
            params = {}
            if link_mac_addr:
                cfg.update({"mac_address": link_mac_addr})
            for k, v in link.items():
                if k == "bond_links":
                    continue
                elif k.startswith("bond"):
                    # Convert OpenStack 'bond_*' to cloud-init 'bond-*' format
                    translated_key = "bond-{}".format(k.split("bond_", 1)[-1])
                    params.update({translated_key: v})
            cfg["params"] = params

            # Generate bond name if not provided
            if cfg.get("name") is None:
                link_name = bond_name_fmt % bond_number
                cfg["name"] = link_name
                curinfo["name"] = link_name
            bond_number += 1

            # Resolve bond member links from IDs to names later
            link_updates.append(
                (
                    cfg,
                    "bond_interfaces",
                    "%s",
                    copy.deepcopy(link["bond_links"]),
                )
            )
        elif link["type"] in ["vlan"]:
            name = "%s.%s" % (link["vlan_link"], link["vlan_id"])
            cfg.update(
                {
                    "name": name,
                    "vlan_id": link["vlan_id"],
                    "mac_address": link["vlan_mac_address"],
                }
            )
            link_updates.append((cfg, "vlan_link", "%s", link["vlan_link"]))
            link_updates.append(
                (cfg, "name", "%%s.%s" % link["vlan_id"], link["vlan_link"])
            )
            curinfo.update({"mac": link["vlan_mac_address"], "name": name})
        elif link["type"] in KNOWN_BRIDGE_TYPES:
            # Configure guest-side Linux bridge
            cfg.update({"type": "bridge"})
            if link_mac_addr:
                cfg.update({"mac_address": link_mac_addr})

            # Collect bridge parameters
            params = {}
            if "bridge_ageing" in link:
                params["bridge_ageing"] = link["bridge_ageing"]
            if "bridge_bridgeprio" in link:
                params["bridge_bridgeprio"] = link["bridge_bridgeprio"]
            if "bridge_fd" in link:
                params["bridge_fd"] = link["bridge_fd"]
            if "bridge_hello" in link:
                params["bridge_hello"] = link["bridge_hello"]
            if "bridge_hw" in link:
                params["bridge_hw"] = link["bridge_hw"]
            if "bridge_maxage" in link:
                params["bridge_maxage"] = link["bridge_maxage"]
            if "bridge_maxwait" in link:
                params["bridge_maxwait"] = link["bridge_maxwait"]
            if "bridge_pathcost" in link:
                params["bridge_pathcost"] = link["bridge_pathcost"]
            if "bridge_portprio" in link:
                params["bridge_portprio"] = link["bridge_portprio"]
            if "bridge_ports" in link:
                params["bridge_ports"] = link["bridge_ports"]
            if "bridge_stp" in link:
                params["bridge_stp"] = link["bridge_stp"]
            if "bridge_waitport" in link:
                params["bridge_waitport"] = link["bridge_waitport"]
            if params:
                cfg["params"] = params

            # Handle accept-ra if specified
            if "accept-ra" in link:
                cfg["accept-ra"] = link["accept-ra"]

            # Resolve bridge member links from IDs to names later
            link_updates.append(
                (
                    cfg,
                    "bridge_interfaces",
                    "%s",
                    copy.deepcopy(link.get("bridge_links", [])),
                )
            )
        else:
            if link["type"] not in KNOWN_PHYSICAL_TYPES:
                LOG.warning(
                    "Unknown network_data link type (%s); treating as"
                    " physical",
                    link["type"],
                )
            cfg.update({"type": "physical", "mac_address": link_mac_addr})

        config.append(cfg)
        link_id_info[curinfo["id"]] = curinfo

    need_names = [
        d for d in config if d.get("type") == "physical" and "name" not in d
    ]

    if need_names or link_updates:
        if known_macs is None:
            # Get mapping of MAC addresses to interface names
            known_macs = {}
            for syspath in glob.glob('/sys/class/net/*'):
                ifname = os.path.basename(syspath)
                if ifname == 'lo':  # Skip loopback
                    continue
                mac_path = os.path.join(syspath, 'address')
                if os.path.exists(mac_path):
                    with open(mac_path, 'r') as f:
                        mac = f.read().strip().lower()
                        if mac:
                            known_macs[mac] = ifname

        # Map link IDs to interface names
        for _link_id, info in link_id_info.items():
            if info.get("name"):
                continue
            if info.get("mac") in known_macs:
                info["name"] = known_macs[info["mac"]]

        for d in need_names:
            mac = d.get("mac_address")
            if not mac:
                raise ValueError("No mac_address or name entry for %s" % d)
            if mac not in known_macs:
                raise ValueError("Unable to find a system nic for %s" % d)
            d["name"] = known_macs[mac]

        for cfg, key, fmt, targets in link_updates:
            if isinstance(targets, (list, tuple)):
                cfg[key] = [
                    fmt % link_id_info[target]["name"] for target in targets
                ]
            else:
                cfg[key] = fmt % link_id_info[targets]["name"]

    for service in services:
        cfg = copy.deepcopy(service)
        cfg.update({"type": "nameserver"})
        config.append(cfg)

    return {"version": 1, "config": config}


def prepare_network_config(network_data):
    """Prepare network config for NoCloud datasource.

    Detects if network_data is in OpenStack format and converts it to
    cloud-init v1 format. If already in cloud-init format, returns as-is.

    :param network_data: Network configuration dictionary
    :returns: Cloud-init v1 format dictionary or original data
    """
    if not network_data:
        return None

    # Detect OpenStack format (links/networks) vs cloud-init (version/config)
    is_openstack = (
        isinstance(network_data, dict)
        and 'links' in network_data
        and 'networks' in network_data
        and not ('version' in network_data and 'config' in network_data)
    )

    if is_openstack:
        LOG.info("Detected OpenStack network_data.json format, converting...")
        try:
            network_config = convert_net_json(
                network_json=network_data,
                known_macs=None
            )
            LOG.info("Successfully converted OpenStack network format")
            return network_config
        except Exception as e:
            LOG.error(
                "Failed to convert OpenStack network format: %s", e
            )
            raise
    else:
        # Already in cloud-init v1 or v2 format
        LOG.info("Network data appears to be in cloud-init format")
        return network_data
