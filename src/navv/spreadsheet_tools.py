#!/usr/bin/env python3

# Copyright 2024 Battelle Energy Alliance, LLC

import os
import itertools
from collections import Counter
import socket
from copy import copy
import json
import pickle
import string
import random

import openpyxl
import openpyxl.styles
from openpyxl.styles import Alignment
from openpyxl.worksheet.table import Table
import netaddr
from tqdm import tqdm

from navv import data_types
from navv.utilities import timeit
from navv.message_handler import warning_msg, info_msg
from navv.geolocation import Geolocator


DATA_PKL_FILE = os.path.join(os.path.dirname(__file__), "data", "data.pkl")
COL_NAMES = [
    "Count",
    "Src_IP",
    "Src_Hostname",
    "Src_Network",
    "Src_Geo",
    "Dest_IP",
    "Dst_Hostname",
    "Dst_Network",
    "Dst_Geo",
    "Port",
    "Service",
    "Proto",
    "Conn_State",
    "Notes",
]
HEADER_STYLE = openpyxl.styles.NamedStyle(
    name="header_style",
    font=openpyxl.styles.Font(name="Calibri", size=11, bold=True),
    fill=openpyxl.styles.PatternFill("solid", fgColor="4286F4"),
)
IPV6_CELL_COLOR = (
    openpyxl.styles.PatternFill("solid", fgColor="FFFFFF"),
    openpyxl.styles.Font(name="Calibri", size=11, color="ff0000"),
)
EXTERNAL_NETWORK_CELL_COLOR = (
    openpyxl.styles.PatternFill("solid", fgColor="030303"),
    openpyxl.styles.Font(name="Calibri", size=11, color="ffff00"),
)
INTERNAL_NETWORK_CELL_COLOR = (
    openpyxl.styles.PatternFill("solid", fgColor="ffff00"),
    openpyxl.styles.Font(name="Calibri", size=11, color="000000"),
)
ICMP_CELL_COLOR = (
    openpyxl.styles.PatternFill("solid", fgColor="ff33cc"),
    openpyxl.styles.Font(name="Calibri", size=11, color="000000"),
)
UNKNOWN_EXTERNAL_CELL_COLOR = (
    openpyxl.styles.PatternFill("solid", fgColor="ffffff"),
    openpyxl.styles.Font(name="Calibri", size=11, color="000000"),
)
ALREADY_UNRESOLVED = list()


def _apply_header_style(cell):
    """Apply header styling without using a NamedStyle, avoiding duplicate-style errors
    when writing to an existing workbook that already has 'header_style' registered."""
    cell.font = openpyxl.styles.Font(name="Calibri", size=11, bold=True)
    cell.fill = openpyxl.styles.PatternFill("solid", fgColor="4286F4")

@timeit
def get_workbook(file_name):
    """Create the blank Inventory and Segment sheets for data input into the tool"""
    if os.path.isfile(file_name):
        wb = openpyxl.load_workbook(file_name)
    else:
        wb = openpyxl.Workbook()
        inv_sheet = wb.active
        inv_sheet.title = "Inventory Input"
        seg_sheet = wb.create_sheet("Segments")

        _apply_header_style(inv_sheet.cell(row=1, column=1, value="IP"))
        _apply_header_style(inv_sheet.cell(row=1, column=2, value="Name"))

        _apply_header_style(seg_sheet.cell(row=1, column=1, value="Name"))
        _apply_header_style(seg_sheet.cell(row=1, column=2, value="Description"))
        _apply_header_style(seg_sheet.cell(row=1, column=3, value="CIDR"))
        _apply_header_style(seg_sheet.cell(row=1, column=4, value="Purdue Level"))
    return wb


@timeit
def get_inventory_data(ws, **kwargs):
    inventory = dict()
    for row in itertools.islice(ws.iter_rows(), 1, None):
        if not row[0].value or not row[1].value:
            continue
        inventory[row[0].value] = data_types.InventoryItem(
            ip=row[0].value,
            name=row[1].value,
            color=(copy(row[0].fill), copy(row[0].font)),
            mac_address="",
            vendor=""
        )
    return inventory


@timeit
def get_segments_data(ws):
    segments = []
    for row in itertools.islice(ws.iter_rows(), 1, None):
        if not row[2].value:
            continue
        network_ip = row[2].value
        purdue_level = str(row[3].value).strip() if len(row) > 3 and row[3].value else "Unknown"
        
        segments.append(
            data_types.Segment(
                name=row[0].value,
                description=row[1].value,
                network=netaddr.IPNetwork(network_ip),
                color=[copy(row[0].fill), copy(row[0].font)],
                purdue_level=purdue_level,
            )
        )
    return segments


def get_package_data():
    """Load services and conn_states data into memory"""
    with open(DATA_PKL_FILE, "rb") as f:
        services, conn_states = pickle.load(f)
    return services, conn_states


def read_existing_notes(wb):
    """Read existing notes from the Analysis sheet if it exists.
    
    Returns a dictionary keyed by a tuple of (src_ip, dest_ip, port, proto, conn_state)
    with the note as the value.
    """
    notes_dict = {}
    
    if "Analysis" not in wb.sheetnames:
        return notes_dict
    
    sheet = wb["Analysis"]
    
    # Check if sheet has data (more than just header row)
    if sheet.max_row <= 1:
        return notes_dict
    
    info_msg("Reading existing notes from Analysis sheet...")
    
    # Dynamically find column indices based on headers
    header_row = next(sheet.iter_rows(min_row=1, max_row=1))
    headers = {cell.value: idx for idx, cell in enumerate(header_row) if cell.value is not None}
    
    required_cols = ["Src_IP", "Dest_IP", "Port", "Proto", "Conn_State", "Notes"]
    
    # Check if we have all required columns
    if not all(col in headers for col in required_cols):
        warning_msg("Could not find all required columns in Analysis sheet. Notes may not be preserved.")
        return notes_dict
        
    src_ip_idx = headers["Src_IP"]
    dest_ip_idx = headers["Dest_IP"]
    port_idx = headers["Port"]
    proto_idx = headers["Proto"]
    conn_state_idx = headers["Conn_State"]
    notes_idx = headers["Notes"]
    
    # Iterate through rows starting from row 2 (skip header)
    for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row):
        try:
            # Extract key fields
            src_ip = row[src_ip_idx].value
            dest_ip = row[dest_ip_idx].value
            port = row[port_idx].value
            proto = row[proto_idx].value
            conn_state = row[conn_state_idx].value
            note = row[notes_idx].value
            
            # Only store if we have valid key data and a non-empty note
            if src_ip and dest_ip and port is not None and proto and conn_state:
                # Convert port to int for consistency
                try:
                    port = int(port)
                except (ValueError, TypeError):
                    continue
                
                # Create key tuple
                key = (str(src_ip), str(dest_ip), port, str(proto), str(conn_state))
                
                # Store note if it's not None or empty
                if note:
                    notes_dict[key] = str(note)
        except (IndexError, AttributeError):
            # Skip malformed rows
            continue
    
    info_msg(f"Found {len(notes_dict)} existing notes")
    return notes_dict


@timeit
def create_analysis_array(sort_input, **kwargs):
    arr = []
    # Sort first by item (alphabetically)
    items = sorted(Counter(sort_input).items(), key=lambda x: x[0])
    # Then sort by count (descending). Python sort is stable, so items with same count remain alphabetically sorted.
    counted = sorted(items, key=lambda x: x[1], reverse=True)
    
    for item, count in counted:
        cells = item.split("\t")
        arr.append(
            data_types.AnalysisRowItem(
                count=str(count),
                src_ip=cells[0],
                dest_ip=cells[1],
                port=cells[2],
                proto=cells[3],
                conn=cells[4],
            )
        )

    return arr


@timeit
def perform_analysis(
    wb,
    rows,
    services,
    conn_states,
    inventory,
    segments,
    dns_data,
    json_path,
    ext_IPs,
    unk_int_IPs,
    purdue_violations=None,
    sankey_data=None,
    verified_sankey_data=None,
    macro_sankey_data=None,
    verified_macro_sankey_data=None,
    macro_link_colors=None,
    geolocator=None,
    ext_dns_cache=None,
    ip_to_mac_label=None,
    **kwargs,
):
    def normalize_purdue(level_str, segment_name):
        level_str = str(level_str).strip()
        if segment_name == "External" or str(level_str).upper().replace("L", "") == "7":
            return "5"
        if level_str == "Unknown":
            return "Unknown"
        return str(level_str).upper().replace("L", "")

    if purdue_violations is None: purdue_violations = []
    if sankey_data is None: sankey_data = {}
    if verified_sankey_data is None: verified_sankey_data = {}
    if macro_sankey_data is None: macro_sankey_data = {}
    if verified_macro_sankey_data is None: verified_macro_sankey_data = {}
    if macro_link_colors is None: macro_link_colors = {}
    # Read existing notes before creating new sheet
    existing_notes = read_existing_notes(wb)
    
    sheet = make_sheet(wb, "Analysis", idx=0)
    sheet.append(
        [
            "Count",
            "Src_IP",
            "Src_MAC",
            "Src_Hostname",
            "Src_Network",
            "Src_Purdue",
            "Src_Geo",
            "Dest_IP",
            "Dest_MAC",
            "Dst_Hostname",
            "Dst_Network",
            "Dst_Purdue",
            "Dst_Geo",
            "Port",
            "Service",
            "Service_Desc",
            "Proto",
            "Conn_State",
            "Direction",
            "Notes",
        ]
    )
    
    # Initialize external DNS cache if not provided
    if ext_dns_cache is None:
        ext_dns_cache = {}
    
    # We pass the segments list directly; we no longer explode CIDRs into massive dictionaries
    segment_dict = segments
    
    # Create IP result cache (optimization)
    ip_result_cache = {}
    
    warning_msg("this may take a while...")
    for row_index, row in enumerate(tqdm(rows), start=2):
        # Use IP result cache to avoid re-processing same IPs
        if row.src_ip not in ip_result_cache:
            ip_result_cache[row.src_ip] = handle_ip(
                row.src_ip, dns_data, inventory, segment_dict, ext_IPs, unk_int_IPs, ext_dns_cache
            )
        row.src_desc = ip_result_cache[row.src_ip]
        
        if row.dest_ip not in ip_result_cache:
            ip_result_cache[row.dest_ip] = handle_ip(
                row.dest_ip, dns_data, inventory, segment_dict, ext_IPs, unk_int_IPs, ext_dns_cache
            )
        row.dest_desc = ip_result_cache[row.dest_ip]
        
        # Add geolocation lookup for external IPs only
        if geolocator and geolocator.enabled:
            row.src_geo = "" if geolocator.is_internal_ip(row.src_ip) else (geolocator.lookup(row.src_ip) or "")
            row.dst_geo = "" if geolocator.is_internal_ip(row.dest_ip) else (geolocator.lookup(row.dest_ip) or "")
        else:
            row.src_geo = ""
            row.dst_geo = ""
            
        # Assign MAC addresses based on the IP
        row.src_mac = ip_to_mac_label.get(row.src_ip, "") if ip_to_mac_label else ""
        row.dst_mac = ip_to_mac_label.get(row.dest_ip, "") if ip_to_mac_label else ""
            
        src_seg = row.src_desc[2]
        dst_seg = row.dest_desc[2]
        
        if src_seg == "External" and dst_seg == "External":
            row.direction = "External -> External"
        elif src_seg == "External":
            row.direction = "External -> Internal (Ingress)"
        elif dst_seg == "External":
            row.direction = "Internal -> External (Egress)"
        else:
            row.direction = "Internal -> Internal (Lateral)"
            
        # Collect Sankey data
        # Group all unresolved external IPs into a single "Internet" node
        sankey_src = "Internet" if src_seg == "External" else f"{src_seg} [{row.src_desc[3]}]"
        sankey_dst = "Internet" if dst_seg == "External" else f"{dst_seg} [{row.dest_desc[3]}]"
        
        sankey_key = (sankey_src, sankey_dst)
        sankey_data[sankey_key] = sankey_data.get(sankey_key, 0) + int(row.count)
        
        if row.conn in ["SF", "S1", "OTH"]:
            verified_sankey_data[sankey_key] = verified_sankey_data.get(sankey_key, 0) + int(row.count)
            
        # Macro Sankey Logic
        sp_clean = normalize_purdue(row.src_desc[3], src_seg)
        dp_clean = normalize_purdue(row.dest_desc[3], dst_seg)
        
        macro_src_node = f"Level {sp_clean}" if sp_clean != "Unknown" else "Unknown"
        macro_dst_node = f"Level {dp_clean}" if dp_clean != "Unknown" else "Unknown"
        
        if macro_src_node != "Unknown" and macro_dst_node != "Unknown":
            macro_links = []
            macro_links.append((sankey_src, macro_src_node))
            if sp_clean != dp_clean:
                macro_links.append((macro_src_node, macro_dst_node))
            macro_links.append((macro_dst_node, sankey_dst))
            
            for link in macro_links:
                macro_sankey_data[link] = macro_sankey_data.get(link, 0) + int(row.count)
                if row.conn in ["SF", "S1", "OTH"]:
                    verified_macro_sankey_data[link] = verified_macro_sankey_data.get(link, 0) + int(row.count)
        
        # Check Purdue violation
        try:
            if sp_clean != "Unknown" and dp_clean != "Unknown":
                s_lvl = float(sp_clean)
                d_lvl = float(dp_clean)
                if abs(s_lvl - d_lvl) > 1.5:
                    purdue_violations.append(row)
                    # Mark the specific layer-to-layer link as a violation (red)
                    violating_link = (macro_src_node, macro_dst_node)
                    macro_link_colors[violating_link] = "rgba(255, 0, 0, 0.4)"
        except Exception:
            pass
        
        handle_service(row, services)
        row.conn = (row.conn, conn_states[row.conn])
        
        # Lookup existing note for this row
        # Key: (src_ip, dest_ip, port, proto, conn_state)
        note_key = (row.src_ip, row.dest_ip, int(row.port), row.proto, row.conn[0])
        row.notes = existing_notes.get(note_key, "")
        
        write_row_to_sheet(row, row_index, sheet)
    
    tab = Table(displayName="AnalysisTable", ref=f"A1:T{len(rows)+1}")
    sheet.add_table(tab)

    # Hide geolocation and mac columns by default (users can unhide in Excel)
    sheet.column_dimensions['C'].hidden = True  # Src_MAC
    sheet.column_dimensions['F'].hidden = True  # Src_Purdue
    sheet.column_dimensions['G'].hidden = True  # Src_Geo
    sheet.column_dimensions['I'].hidden = True  # Dest_MAC
    sheet.column_dimensions['L'].hidden = True  # Dst_Purdue
    sheet.column_dimensions['M'].hidden = True  # Dst_Geo
    sheet.column_dimensions['P'].hidden = True  # Service_Desc

    # write lookup data to json file for future use
    with open(json_path, "w+") as fp:
        json.dump(dns_data, fp)


def write_row_to_sheet(row, row_index, sheet):
    sheet.cell(row=row_index, column=1, value=int(row.count))

    src_IP = sheet.cell(row=row_index, column=2, value=row.src_ip)
    src_IP.fill = row.src_desc[1][0]
    src_IP.font = row.src_desc[1][1]

    src_MAC = sheet.cell(row=row_index, column=3, value=row.src_mac)
    src_MAC.fill = row.src_desc[1][0]
    src_MAC.font = row.src_desc[1][1]

    src_Host = sheet.cell(row=row_index, column=4, value=row.src_desc[0])
    src_Host.fill = row.src_desc[1][0]
    src_Host.font = row.src_desc[1][1]

    src_Network = sheet.cell(row=row_index, column=5, value=row.src_desc[2])
    src_Network.fill = row.src_desc[1][0]
    src_Network.font = row.src_desc[1][1]

    src_Purdue = sheet.cell(row=row_index, column=6, value=row.src_desc[3])
    src_Purdue.fill = row.src_desc[1][0]
    src_Purdue.font = row.src_desc[1][1]

    # Add Src_Geo column
    src_Geo = sheet.cell(row=row_index, column=7, value=row.src_geo)
    src_Geo.fill = row.src_desc[1][0]
    src_Geo.font = row.src_desc[1][1]

    dest_IP = sheet.cell(row=row_index, column=8, value=row.dest_ip)
    dest_IP.fill = row.dest_desc[1][0]
    dest_IP.font = row.dest_desc[1][1]

    dest_MAC = sheet.cell(row=row_index, column=9, value=row.dst_mac)
    dest_MAC.fill = row.dest_desc[1][0]
    dest_MAC.font = row.dest_desc[1][1]

    dest_Host = sheet.cell(row=row_index, column=10, value=row.dest_desc[0])
    dest_Host.fill = row.dest_desc[1][0]
    dest_Host.font = row.dest_desc[1][1]

    dest_Network = sheet.cell(row=row_index, column=11, value=row.dest_desc[2])
    dest_Network.fill = row.dest_desc[1][0]
    dest_Network.font = row.dest_desc[1][1]

    dst_Purdue = sheet.cell(row=row_index, column=12, value=row.dest_desc[3])
    dst_Purdue.fill = row.dest_desc[1][0]
    dst_Purdue.font = row.dest_desc[1][1]

    # Add Dst_Geo column
    dst_Geo = sheet.cell(row=row_index, column=13, value=row.dst_geo)
    dst_Geo.fill = row.dest_desc[1][0]
    dst_Geo.font = row.dest_desc[1][1]

    sheet.cell(row=row_index, column=14, value=int(row.port))

    service_val = str(row.service[0])
    service_desc = ""
    if "(" in service_val and ")" in service_val:
        start_idx = service_val.find("(")
        end_idx = service_val.rfind(")")
        service_desc = service_val[start_idx+1:end_idx].strip()
        service_val = service_val[:start_idx].strip()

    service = sheet.cell(row=row_index, column=15, value=service_val)
    service.fill = row.service[1][0]
    service.font = row.service[1][1]

    service_desc_cell = sheet.cell(row=row_index, column=16, value=service_desc)
    service_desc_cell.fill = row.service[1][0]
    service_desc_cell.font = row.service[1][1]

    sheet.cell(row=row_index, column=17, value=row.proto)

    conn_State = sheet.cell(row=row_index, column=18, value=row.conn[0])
    conn_State.fill = row.conn[1][0]
    conn_State.font = row.conn[1][1]
    
    sheet.cell(row=row_index, column=19, value=row.direction)

    # Write the note (either existing or empty string)
    sheet.cell(row=row_index, column=20, value=row.notes)


def handle_service(row, services):
    # { port: { proto: (name, (fill, font)} }
    if row.port in services and row.proto in services[row.port]:
        row.service = services[row.port][row.proto]
    else:
        if row.proto == "icmp":
            if netaddr.valid_ipv4(row.src_ip):
                row.proto = "ICMPv4"
                service_dict = data_types.icmp4_types
            else:
                row.proto = "ICMPv6"
                service_dict = data_types.icmp6_types
            if row.port in service_dict:
                row.service = (service_dict[row.port], ICMP_CELL_COLOR)
            else:
                row.service = ("unknown icmp", ICMP_CELL_COLOR)
        else:
            row.service = ("unknown service", UNKNOWN_EXTERNAL_CELL_COLOR)


def handle_ip(ip_to_check, dns_data, inventory, segment_dict, ext_IPs, unk_int_IPs, ext_dns_cache=None):
    """Function take IP Address and uses collected dns_data, inventory, and segment information to give IP Addresses in analysis context.

    Priority flow:
        * DHCP Broadcasting
        * Multicast
        * Within Segments identified
            * Resolution by DNS, then Inventory, and then Unknown
            * Appends name if External IP
        * Private Network
            * Resolution by DNS, Inventory, then Unknown
        * External (Public IP space) or Internet
            * Resolution by DNS, cached external DNS lookup, then socket lookup

    This will capture the name description and the color coding identified within the worksheet.
    """
    if ext_dns_cache is None:
        ext_dns_cache = {}
    
    desc_to_change = ("Not Triggered IP", IPV6_CELL_COLOR, "Unknown", "Unknown")
    if ip_to_check == str("0.0.0.0"):
        desc_to_change = (
            "Unassigned IPv4",
            IPV6_CELL_COLOR,
            "Multicast/Broadcast",
            "Unknown"
        )
    elif ip_to_check == str("255.255.255.255"):
        desc_to_change = (
            "IPv4 All Subnet Broadcast",
            IPV6_CELL_COLOR,
            "Multicast/Broadcast",
            "Unknown"
        )
    elif (
        netaddr.valid_ipv6(ip_to_check) or netaddr.IPAddress(ip_to_check).is_multicast()
    ):
        desc_to_change = (
            f"{'IPv6' if netaddr.valid_ipv6(ip_to_check) else 'IPv4'}{'_Multicast' if netaddr.IPAddress(ip_to_check).is_multicast() else ''}",
            IPV6_CELL_COLOR,
            "Multicast/Broadcast",
            "Unknown"
        )
    elif (
        netaddr.IPAddress(ip_to_check).is_link_local()
    ):
        desc_to_change = (
            f"{'IPv6' if netaddr.valid_ipv6(ip_to_check) else 'IPv4'}{'_Link-local' if netaddr.IPAddress(ip_to_check).is_link_local() else ''}",
            IPV6_CELL_COLOR,
            "Link-Local",
            "Unknown"
        )
    else:
        # Check if IP falls within any of our defined segment CIDRs
        segment = None
        try:
            ip_obj = netaddr.IPAddress(ip_to_check)
            for seg in segment_dict:
                if ip_obj in seg.network:
                    segment = seg
                    break
        except Exception:
            pass

        if segment:
            if ip_to_check in dns_data:
                resolution = dns_data[ip_to_check]
            elif ip_to_check in inventory:
                resolution = inventory[ip_to_check].name
            else:
                resolution = f"Unknown device"
                unk_int_IPs.add(ip_to_check)
            if not netaddr.IPAddress(ip_to_check).is_ipv4_private_use():
                resolution = resolution + " {Non-Priv IP}"
            desc_to_change = (
                resolution,
                segment.color,
                segment.name,
                segment.purdue_level
            )
        elif netaddr.IPAddress(ip_to_check).is_ipv4_private_use():
            if ip_to_check in dns_data:
                desc_to_change = (dns_data[ip_to_check], INTERNAL_NETWORK_CELL_COLOR, "Unknown Internal", "Unknown")
            elif ip_to_check in inventory:
                desc_to_change = (inventory[ip_to_check].name, INTERNAL_NETWORK_CELL_COLOR, "Unknown Internal", "Unknown")
            else:
                desc_to_change = ("Unknown Internal address", INTERNAL_NETWORK_CELL_COLOR, "Unknown Internal", "Unknown")
                unk_int_IPs.add(ip_to_check)
        else:
            ext_IPs.add(ip_to_check)
            # Default resolution for external IPs
            resolution = "Unresolved external address"
            
            # Priority: dns_data > inventory > ext_dns_cache > socket lookup
            if ip_to_check in dns_data:
                resolution = dns_data[ip_to_check]
            elif ip_to_check in inventory:
                resolution = inventory[ip_to_check].name + " {Non-Priv IP}"
            elif ip_to_check in ext_dns_cache:
                # Use cached external DNS lookup
                resolution = ext_dns_cache[ip_to_check]
            else:
                # Perform reverse DNS lookup and cache the result
                try:
                    resolution = socket.gethostbyaddr(ip_to_check)[0]
                    # Cache successful lookup
                    ext_dns_cache[ip_to_check] = resolution
                except socket.herror:
                    # Cache the failure too so we don't retry
                    ext_dns_cache[ip_to_check] = "Unresolved external address"
                    ALREADY_UNRESOLVED.append(ip_to_check)
            
            desc_to_change = (resolution, EXTERNAL_NETWORK_CELL_COLOR, "External", "7")
    return desc_to_change


def write_conn_states_sheet(conn_states, wb):
    new_ws = make_sheet(wb, "Conn States", idx=8)
    new_ws.append(["State", "Description"])
    for index, conn_state in enumerate(conn_states, start=2):
        # State column
        state_cell = new_ws[f"A{index}"]
        state_cell.value = conn_state
        state_cell.fill = conn_states[conn_state][0]
        state_cell.font = conn_states[conn_state][1]

        # Description column
        desc_cell = new_ws[f"B{index}"]
        desc_cell.alignment = openpyxl.styles.Alignment(wrap_text=True)
        desc_cell.value = conn_states[conn_state][2]
        desc_cell.fill = conn_states[conn_state][0]
        desc_cell.font = conn_states[conn_state][1]
    auto_adjust_width(new_ws, 100)





def write_snmp_sheet(snmp_df, wb):
    """Write SNMP log data to excel sheet."""
    sheet = make_sheet(wb, "SNMP", idx=4)
    sheet.append(
        ["Src IPv4", "Src Port", "Dest IPv4", "Dest Port", "Version", "Community"]
    )

    for index, row in enumerate(snmp_df.to_dict(orient="records"), start=2):
        # Source IPv4 column
        sheet[f"A{index}"].value = row["src_ip"]

        # Source Port column
        sheet[f"B{index}"].value = row["src_port"]

        # Destination IPv4 column
        sheet[f"C{index}"].value = row["dst_ip"]

        # Destination Port column
        sheet[f"D{index}"].value = row["dst_port"]

        # Version column
        sheet[f"E{index}"].value = row["version"]

        # Community column
        sheet[f"F{index}"].value = row["community"]

        # Add styling to every other row
        if index % 2 == 0:
            for cell in sheet[f"{index}:{index}"]:
                cell.fill = openpyxl.styles.PatternFill("solid", fgColor="AAAAAA")

    auto_adjust_width(sheet, 40)


def write_externals_sheet(IPs, wb, geolocator=None, ext_dns_cache=None):
    if ext_dns_cache is None:
        ext_dns_cache = {}
    ext_sheet = make_sheet(wb, "Externals", idx=5)
    ext_sheet.append(["External IP", "Country", "Region", "City", "ISP", "Domain", "Reputation"])
    for row_index, IP in enumerate(sorted(IPs), start=2):
        cell = ext_sheet[f"A{row_index}"]
        cell.value = IP
        
        geo_dict = {"country": "", "region": "", "city": "", "isp": ""}
        if geolocator and geolocator.enabled:
            geo_dict = geolocator.lookup_external(IP)
            
        ext_sheet[f"B{row_index}"].value = geo_dict["country"]
        ext_sheet[f"C{row_index}"].value = geo_dict["region"]
        ext_sheet[f"D{row_index}"].value = geo_dict["city"]
        ext_sheet[f"E{row_index}"].value = geo_dict["isp"]
        ext_sheet[f"F{row_index}"].value = ext_dns_cache.get(IP, "")
        ext_sheet[f"G{row_index}"].value = "" # Reputation
    
    if len(IPs) > 0:
        tab = Table(displayName="ExternalsTable", ref=f"A1:G{len(IPs)+1}")
        ext_sheet.add_table(tab)

    auto_adjust_width(ext_sheet)


def write_unknown_internals_sheet(IPs, wb):
    int_sheet = make_sheet(wb, "Unknown Internals", idx=6)
    int_sheet.append(["Unknown Internal IP"])
    for row_index, IP in enumerate(sorted(IPs), start=2):
        cell = int_sheet[f"A{row_index}"]
        cell.value = IP
        if row_index % 2 == 0:
            cell.fill = openpyxl.styles.PatternFill("solid", fgColor="AAAAAA")
    auto_adjust_width(int_sheet)


def write_stats_sheet(wb, stats):
    stats_sheet = make_sheet(wb, "Stats", idx=7)
    stats_sheet.append(
        ["Length of Capture time"]
        + [column for column in stats if column != "Length of Capture time"]
    )
    stats_sheet["A2"] = stats.pop("Length of Capture time")
    for col_index, stat in enumerate(stats, 1):
        stats_sheet[f"{string.ascii_uppercase[col_index]}2"].value = stats[stat]
    auto_adjust_width(stats_sheet)

def write_internal_hosts_sheet(mac_df, wb, inventory, segment_dict):
    """Fill spreadsheet with IP -> MAC, Manufacturer, Segment, Purdue Level, Inventory Status"""
    sheet = make_sheet(wb, "Internal Hosts", idx=2)
    sheet.append(
        ["IP Address", "MAC Address", "Manufacturer", "Network Segment", "Purdue Level", "In Inventory?", "Recommendation"]
    )
    filtered_rows = []
    import netaddr
    for row in mac_df.to_dict(orient="records"):
        ip = row["ip"]
        try:
            if ip in ["0.0.0.0", "255.255.255.255"] or netaddr.valid_ipv6(ip):
                continue
            ip_obj = netaddr.IPAddress(ip)
            if ip_obj.is_multicast() or ip_obj.is_link_local() or ip_obj.is_loopback():
                continue
            in_segment = any(ip_obj in seg.network for seg in segment_dict)
            if not ip_obj.is_ipv4_private_use() and not in_segment:
                continue
        except Exception:
            continue
        filtered_rows.append(row)

    for index, row in enumerate(filtered_rows, start=2):
        ip = row["ip"]
        mac = row["mac"]
        vendor = row["vendor"]
        
        segment_name = "Unknown Internal"
        purdue_level = "Unknown"
        in_inventory = "Yes" if ip in inventory else "No"
        
        try:
            ip_obj = netaddr.IPAddress(ip)
            for seg in segment_dict:
                if ip_obj in seg.network:
                    segment_name = seg.name
                    purdue_level = seg.purdue_level
                    break
        except Exception:
            pass
            
        sheet[f"A{index}"].value = ip
        sheet[f"B{index}"].value = mac
        sheet[f"C{index}"].value = vendor
        sheet[f"D{index}"].value = segment_name
        sheet[f"E{index}"].value = purdue_level
        sheet[f"F{index}"].value = in_inventory
        sheet[f"G{index}"].value = "" # Recommendation

    if len(filtered_rows) > 0:
        tab = Table(displayName="InternalHostsTable", ref=f"A1:G{len(filtered_rows)+1}")
        sheet.add_table(tab)
    auto_adjust_width(sheet)

def write_legend_sheet(wb):
    sheet = make_sheet(wb, "Legend & ReadMe", idx=0)
    sheet.append(["NAVV Network Analysis Legend"])
    sheet.append([""])
    sheet.append(["Colors", "Meaning"])
    sheet.append(["Red Warning", "IPv6, Broadcast, Multicast, or Link-Local traffic. Expected, but highlight misconfigurations."])
    sheet.append(["Yellow Background", "Internal Network Traffic (Device sits in RFC1918 or segment space)."])
    sheet.append(["Black Background / Yellow Text", "External Network Traffic. Warning: Reach in or Reach out!"])
    sheet.append(["Pink Background", "ICMP Traffic (Pings)."])
    sheet.append([""])
    sheet.append(["Tabs", "Purpose"])
    sheet.append(["Analysis", "The core analysis comparing Src IP, Dest IP, Port, and Protocol over time."])
    sheet.append(["Purdue Violations", "Automated extract of traffic crossing multiple Purdue tiers."])
    sheet.append(["Internal Hosts", "Inventory of all actively communicating internal IPs mapped to MACs and Segments."])
    sheet.append(["Externals", "Enriched list of all external/Internet IP communications."])
    sheet.append(["SNMP", "Audit of all cleartext SNMP Version & Community strings sent and received."])
    sheet.append(["Unknown Internals", "A list of Internal IPs that have no DNS or Inventory label."])
    
    # Quick styling
    from openpyxl.styles import Font, PatternFill
    sheet["A1"].font = Font(bold=True, size=14)
    sheet["A3"].font = Font(bold=True)
    sheet["B3"].font = Font(bold=True)
    sheet["A9"].font = Font(bold=True)
    sheet["A4"].fill = IPV6_CELL_COLOR[0]
    sheet["A4"].font = IPV6_CELL_COLOR[1]
    
    sheet["A5"].fill = INTERNAL_NETWORK_CELL_COLOR[0]
    sheet["A5"].font = INTERNAL_NETWORK_CELL_COLOR[1]
    
    sheet["A6"].fill = EXTERNAL_NETWORK_CELL_COLOR[0]
    sheet["A6"].font = EXTERNAL_NETWORK_CELL_COLOR[1]
    
    sheet["A7"].fill = ICMP_CELL_COLOR[0]
    sheet["A7"].font = ICMP_CELL_COLOR[1]
    
    auto_adjust_width(sheet)

def write_purdue_violations_sheet(violations, wb):
    sheet = make_sheet(wb, "Purdue Violations", idx=1)
    sheet.append(
        [
            "Count",
            "Src_IP",
            "Src_Hostname",
            "Src_Network",
            "Src_Purdue",
            "Dest_IP",
            "Dst_Hostname",
            "Dst_Network",
            "Dst_Purdue",
            "Port",
            "Service",
            "Service Description",
            "Proto",
            "Direction",
        ]
    )
    for row_index, row in enumerate(violations, start=2):
        sheet.cell(row=row_index, column=1, value=int(row.count))
        
        src_IP = sheet.cell(row=row_index, column=2, value=row.src_ip)
        src_IP.fill = row.src_desc[1][0]
        src_IP.font = row.src_desc[1][1]
        
        src_Host = sheet.cell(row=row_index, column=3, value=row.src_desc[0])
        src_Host.fill = row.src_desc[1][0]
        src_Host.font = row.src_desc[1][1]
        
        src_Network = sheet.cell(row=row_index, column=4, value=row.src_desc[2])
        src_Network.fill = row.src_desc[1][0]
        src_Network.font = row.src_desc[1][1]
        
        sheet.cell(row=row_index, column=5, value=row.src_desc[3])
        
        dest_IP = sheet.cell(row=row_index, column=6, value=row.dest_ip)
        dest_IP.fill = row.dest_desc[1][0]
        dest_IP.font = row.dest_desc[1][1]
        
        dest_Host = sheet.cell(row=row_index, column=7, value=row.dest_desc[0])
        dest_Host.fill = row.dest_desc[1][0]
        dest_Host.font = row.dest_desc[1][1]
        
        dest_Network = sheet.cell(row=row_index, column=8, value=row.dest_desc[2])
        dest_Network.fill = row.dest_desc[1][0]
        dest_Network.font = row.dest_desc[1][1]
        
        sheet.cell(row=row_index, column=9, value=row.dest_desc[3])
        sheet.cell(row=row_index, column=10, value=int(row.port))
        
        service_val = str(row.service[0])
        service_desc = ""
        if "(" in service_val and ")" in service_val:
            start_idx = service_val.find("(")
            end_idx = service_val.rfind(")")
            service_desc = service_val[start_idx+1:end_idx].strip()
            service_val = service_val[:start_idx].strip()

        service = sheet.cell(row=row_index, column=11, value=service_val)
        service.fill = row.service[1][0]
        service.font = row.service[1][1]
        
        service_desc_cell = sheet.cell(row=row_index, column=12, value=service_desc)
        service_desc_cell.fill = row.service[1][0]
        service_desc_cell.font = row.service[1][1]
        
        sheet.cell(row=row_index, column=13, value=row.proto)
        sheet.cell(row=row_index, column=14, value=row.direction)
        
    if len(violations) > 0:
        tab = Table(displayName="PurdueViolationsTable", ref=f"A1:N{len(violations)+1}")
        sheet.add_table(tab)
        
    sheet.column_dimensions['L'].hidden = True
    auto_adjust_width(sheet)

def generate_sankey_html(sankey_data, output_path, title="NAVV Purdue Segmentation Flows", link_colors=None):
    nodes = set()
    for (src, dst) in sankey_data.keys():
        nodes.add(src)
        nodes.add(dst)
    nodes = list(nodes)
    
    node_indices = {n: i for i, n in enumerate(nodes)}
    
    sources = []
    targets = []
    values = []
    colors = []
    
    for (src, dst), count in sankey_data.items():
        sources.append(node_indices[src])
        targets.append(node_indices[dst])
        values.append(count)
        if link_colors and (src, dst) in link_colors:
            colors.append(link_colors[(src, dst)])
        else:
            colors.append("rgba(150, 150, 150, 0.3)")
            
    total_connections = sum(values) if values else 1
    
    # Calculate percentage for each node and update labels
    node_labels = []
    for n in nodes:
        n_traffic = sum(count for (src, dst), count in sankey_data.items() if src == n or dst == n)
        pct = (n_traffic / total_connections) * 100
        node_labels.append(f"{n} ({pct:.1f}%)")
        
    # Calculate percentage for each link
    percentages = [f"{(v / total_connections * 100):.1f}" for v in values]
        
    js_data = {
        "nodes": node_labels,
        "sources": sources,
        "targets": targets,
        "values": values,
        "percentages": percentages,
        "colors": colors
    }
    import json
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body, html {{ margin: 0; padding: 0; height: 100%; width: 100%; font-family: sans-serif; }}
            #sankey_div {{ width: 100%; height: 100vh; }}
        </style>
    </head>
    <body>
        <div id="sankey_div"></div>
        <script>
            var data = {json.dumps(js_data)};
            var trace = {{
                type: "sankey",
                orientation: "h",
                node: {{
                    pad: 15,
                    thickness: 20,
                    line: {{ color: "black", width: 0.5 }},
                    label: data.nodes
                }},
                link: {{
                    source: data.sources,
                    target: data.targets,
                    value: data.values,
                    customdata: data.percentages,
                    color: data.colors,
                    hovertemplate: '%{{source.label}} &rarr; %{{target.label}}<br />Connections: %{{value}}<br />Percent of Total: %{{customdata}}%<extra></extra>'
                }}
            }};
            
            var layout = {{
                title: "{title}",
                font: {{ size: 12 }}
            }};
            
            Plotly.newPlot("sankey_div", [trace], layout);
        </script>
    </body>
    </html>
    """
    with open(output_path, "w") as f:
        f.write(html_content)

def make_sheet(wb, sheet_name, idx=None):
    """Create the sheet if it doesn't already exist otherwise remove it and recreate it"""
    if sheet_name in wb.sheetnames:
        wb.remove(wb[sheet_name])
    return wb.create_sheet(sheet_name, index=idx)





def write_data_layer_sheet(zeek_df, wb):
    import pandas as pd
    from openpyxl.worksheet.table import Table
    
    # Group by src_mac, dst_mac, and conn state to count unique connections
    df_grouped = zeek_df.groupby(['src_mac', 'dst_mac', 'conn']).size().reset_index(name='count')
    df_grouped = df_grouped.sort_values(by='count', ascending=False)
    
    sheet = make_sheet(wb, "Data_layer")
    sheet.append(["Count", "Source MAC", "Destination MAC", "Connection State"])
    
    for index, row in enumerate(df_grouped.itertuples(index=False), start=2):
        sheet.cell(row=index, column=1, value=row.count)
        sheet.cell(row=index, column=2, value=row.src_mac)
        sheet.cell(row=index, column=3, value=row.dst_mac)
        sheet.cell(row=index, column=4, value=row.conn)
        
    if len(df_grouped) > 0:
        tab = Table(displayName="DataLayerTable", ref=f"A1:D{len(df_grouped)+1}")
        sheet.add_table(tab)
        
    auto_adjust_width(sheet)


def auto_adjust_width(sheet, width=40):
    """Adjust the width of the columns to fit the data"""
    for col in sheet.columns:
        max_width = max(len(f"{c.value}") for c in col if c.value) + 2
        sheet.column_dimensions[col[0].column_letter].width = (
            width if width < max_width else max_width
        )

def auto_discover_segments(zeek_df, segments):
    def get_random_color():
        r = random.randint(50, 200)
        g = random.randint(50, 200)
        b = random.randint(50, 200)
        return f"FF{r:02X}{g:02X}{b:02X}"
        
    def is_default_color(fill):
        if not fill or fill.patternType is None: return True
        rgb = getattr(fill.fgColor, 'rgb', None)
        if not rgb: return True
        rgb = str(rgb).upper()
        return rgb in ["00000000", "FFFFFFFF", "FFFFFF00", "00FFFFFF", "FF000000", "FFFF0000", "FFFFFF"]
        
    # Recolor existing segments
    for seg in segments:
        fill = seg.color[0]
        if is_default_color(fill):
            new_fill = openpyxl.styles.PatternFill("solid", fgColor=get_random_color())
            new_font = openpyxl.styles.Font(name="Calibri", size=11, color="000000")
            seg.color = [new_fill, new_font]
            
    # Auto-discover subnets
    import pandas as pd
    all_ips = set(pd.concat([zeek_df['src_ip'], zeek_df['dst_ip']]))
    discovered_subnets = set()
    
    for ip in all_ips:
        try:
            ip_obj = netaddr.IPAddress(ip)
            if ip_obj.is_ipv4_private_use():
                found = False
                for seg in segments:
                    if ip_obj in seg.network:
                        found = True
                        break
                if not found:
                    subnet = netaddr.IPNetwork(f"{ip}/24").cidr
                    discovered_subnets.add(str(subnet))
        except Exception:
            pass
            
    for subnet in discovered_subnets:
        new_fill = openpyxl.styles.PatternFill("solid", fgColor=get_random_color())
        new_font = openpyxl.styles.Font(name="Calibri", size=11, color="000000")
        segments.append(
            data_types.Segment(
                name=f"Auto-Discovered {subnet}",
                description="Automatically discovered internal subnet",
                network=netaddr.IPNetwork(subnet),
                color=[new_fill, new_font],
                purdue_level="Unknown"
            )
        )
        
    return segments

def write_segments_sheet(segments, wb):
    sheet = make_sheet(wb, "Segments", idx=1)
    sheet.append(["Name", "Description", "CIDR", "Purdue Level"])
    for cell in sheet[1]:
        _apply_header_style(cell)
        
    for index, seg in enumerate(segments, start=2):
        sheet.cell(row=index, column=1, value=seg.name)
        sheet.cell(row=index, column=2, value=seg.description)
        sheet.cell(row=index, column=3, value=str(seg.network))
        sheet.cell(row=index, column=4, value=seg.purdue_level)
        
        sheet.cell(row=index, column=1).fill = seg.color[0]
        sheet.cell(row=index, column=1).font = seg.color[1]
        sheet.cell(row=index, column=2).fill = seg.color[0]
        sheet.cell(row=index, column=2).font = seg.color[1]
        sheet.cell(row=index, column=3).fill = seg.color[0]
        sheet.cell(row=index, column=3).font = seg.color[1]
        sheet.cell(row=index, column=4).fill = seg.color[0]
        sheet.cell(row=index, column=4).font = seg.color[1]
            
    auto_adjust_width(sheet)

def color_inventory_sheet(wb, inventory_tab_name, segments):
    if inventory_tab_name not in wb.sheetnames:
        return
    sheet = wb[inventory_tab_name]
    for row in sheet.iter_rows(min_row=2):
        if not row[0].value:
            continue
        ip_val = str(row[0].value).strip()
        try:
            ip_obj = netaddr.IPAddress(ip_val)
            for seg in segments:
                if ip_obj in seg.network:
                    for cell in row:
                        if cell.value:
                            cell.fill = seg.color[0]
                            cell.font = seg.color[1]
                    break
        except Exception:
            pass
