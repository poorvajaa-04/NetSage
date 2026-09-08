r"""
Network topology definition.

A small but realistic enterprise topology:

        FW1 (edge firewall)
         |
        CORE1 --- CORE2 (redundant core)
        /    \
   DIST-R1   DIST-R2
    /   \        \
ACC-SW1 ACC-SW2  ACC-SW3
   |       |         |
 SRV1    SRV2      SRV3
"""

import networkx as nx

DEVICE_ROLES = {
    "FW1": "firewall",
    "CORE1": "core_router",
    "CORE2": "core_router",
    "DIST-R1": "dist_router",
    "DIST-R2": "dist_router",
    "ACC-SW1": "access_switch",
    "ACC-SW2": "access_switch",
    "ACC-SW3": "access_switch",
    "SRV1": "server",
    "SRV2": "server",
    "SRV3": "server",
}

EDGES = [
    ("FW1", "CORE1"),
    ("CORE1", "CORE2"),
    ("CORE1", "DIST-R1"),
    ("CORE1", "DIST-R2"),
    ("DIST-R1", "ACC-SW1"),
    ("DIST-R1", "ACC-SW2"),
    ("DIST-R2", "ACC-SW3"),
    ("ACC-SW1", "SRV1"),
    ("ACC-SW2", "SRV2"),
    ("ACC-SW3", "SRV3"),
]


def build_topology() -> nx.Graph:
    g = nx.Graph()
    for dev, role in DEVICE_ROLES.items():
        g.add_node(dev, role=role)
    g.add_edges_from(EDGES)
    return g


def devices():
    return list(DEVICE_ROLES.keys())