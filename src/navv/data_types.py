#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

from dataclasses import dataclass, field
import netaddr


@dataclass
class InventoryItem:
    ip: str
    name: str
    mac_address: str
    vendor: str
    color: str


@dataclass
class Segment:
    name: str
    description: str
    network: str
    color: str


@dataclass
class AnalysisRowItem:
    count: int
    src_ip: str
    dest_ip: str
    port: int
    proto: str
    conn: str
    service: str = ""
    dest_desc: str = ""
    src_desc: str = ""
    notes: str = ""


icmp4_types = {
    "0": "Echo Reply",
    "1": "Unassigned",
    "2": "Unassigned",
    "3": "Destination Unreachable",
    "4": "Source Quench (Deprecated)",
    "5": "Redirect",
    "6": "Alternate Host Address (Deprecated)",
    "7": "Unassigned",
    "8": "Echo",
    "9": "Router Advertisement",
    "10": "Router Solicitation",
    "11": "Time Exceeded",
    "12": "Parameter Problem",
    "13": "Timestamp",
    "14": "Timestamp Reply",
    "15": "Information Request (Deprecated)",
    "16": "Information Reply (Deprecated)",
    "17": "Address Mask Request (Deprecated)",
    "18": "Address Mask Reply (Deprecated)",
    "19": "Reserved (for Security)",
    "30": "Traceroute (Deprecated)",
    "31": "Datagram Conversion Error (Deprecated)",
    "32": "Mobile Host Redirect (Deprecated)",
    "33": "IPv6 Where-Are-You (Deprecated)",
    "34": "IPv6 I-Am-Here (Deprecated)",
    "35": "Mobile Registration Request (Deprecated)",
    "36": "Mobile Registration Reply (Deprecated)",
    "37": "Domain Name Request (Deprecated)",
    "38": "Domain Name Reply (Deprecated)",
    "39": "SKIP (Deprecated)",
    "40": "Photuris",
    "42": "Extended Echo Request",
    "43": "Extended Echo Reply",
    "253": "RFC3692-style Experiment 1",
    "254": "RFC3692-style Experiment 2",
    "255": "Reserved",
}

icmp6_types = {
    "0": "Reserved",
    "1": "Destination Unreachable",
    "2": "Packet Too Big",
    "3": "Time Exceeded",
    "4": "Parameter Problem",
    "100": "Private experimentation",
    "101": "Private experimentation",
    "127": "Reserved for expansion of ICMPv6 error messages",
    "128": "Echo Request",
    "129": "Echo Reply",
    "130": "Multicast Listener Query",
    "131": "Multicast Listener Report",
    "132": "Multicast Listener Done",
    "133": "Router Solicitation",
    "134": "Router Advertisement",
    "135": "Neighbor Solicitation",
    "136": "Neighbor Advertisement",
    "137": "Redirect Message",
    "138": "Router Renumbering",
    "139": "ICMP Node Information Query",
    "140": "ICMP Node Information Response",
    "141": "Inverse Neighbor Discovery Solicitation Message",
    "142": "Inverse Neighbor Discovery Advertisement Message",
    "143": "Version 2 Multicast Listener Report",
    "144": "Home Agent Address Discovery Request Message",
    "145": "Home Agent Address Discovery Reply Message",
    "146": "Mobile Prefix Solicitation",
    "147": "Mobile Prefix Advertisment",
    "148": "Certification Path Solicitation Message",
    "149": "Certification Path Advertisement Message",
    "150": "ICMP messages utilized by experimental mobility protocols such as Seamoby",
    "151": "Multicast Router Advertisement",
    "152": "Multicast Router Solicitation",
    "153": "Multicast Router Termination",
    "154": "FMIPv6 Messages",
    "155": "RPL Control Message",
    "156": "ILNPv6 Locator Update Message",
    "157": "Duplicate Address Request",
    "158": "Duplicate Address Confirmation",
    "159": "MPL Control Message",
    "160": "Extended Echo Request",
    "161": "Extended Echo Reply",
    "200": "Private experimentation",
    "201": "Private experimentation",
    "255": "Reserved for expansion of ICMPv6 informational messages",
}
