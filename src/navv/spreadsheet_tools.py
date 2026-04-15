#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

import os
import itertools
from collections import Counter
import socket
from copy import copy
import json
import pkg_resources
import pickle
import string

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


DATA_PKL_FILE = pkg_resources.resource_filename(__name__, "data/data.pkl")
COL_NAMES = [
    "Count",
    "Src_IP",
    "Src_Desc",
    "Src_Geo",
    "Dest_IP",
    "Dest_Desc",
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

        inv_sheet.cell(row=1, column=1, value="IP").style = HEADER_STYLE
        inv_sheet.cell(row=1, column=2, value="Name").style = HEADER_STYLE

        seg_sheet.cell(row=1, column=1, value="Name").style = HEADER_STYLE
        seg_sheet.cell(row=1, column=2, value="Description").style = HEADER_STYLE
        seg_sheet.cell(row=1, column=3, value="CIDR").style = HEADER_STYLE
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
    network_ip = ""
    for row in itertools.islice(ws.iter_rows(), 1, None):
        if not row[2].value:
            continue
        network_ip = row[2].value
        network_ips = [str(ip) for ip in netaddr.IPNetwork(network_ip)]
        for ip in network_ips:
            segments.append(
                data_types.Segment(
                    name=row[0].value,
                    description=row[1].value,
                    network=ip,
                    color=[copy(row[0].fill), copy(row[0].font)],
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
    
    # Iterate through rows starting from row 2 (skip header)
    for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row):
        try:
            # Extract key fields: Src_IP (col 2), Dest_IP (col 5), Port (col 8), Proto (col 10), Conn_State (col 11)
            src_ip = row[1].value  # Column B (index 1)
            dest_ip = row[4].value  # Column E (index 4)
            port = row[7].value  # Column H (index 7)
            proto = row[9].value  # Column J (index 9)
            conn_state = row[10].value  # Column K (index 10)
            note = row[11].value  # Column L (index 11) - Notes
            
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
    # sort by count and source IP
    counted = sorted(
        list(
            str(count) + "\t" + item
            for item, count in sorted(Counter(sort_input).items(), key=lambda x: x[0])
        ),
        key=lambda x: int(x.split("\t")[0]),
        reverse=True,
    )
    for row in counted:
        cells = row.split("\t")
        arr.append(
            data_types.AnalysisRowItem(
                count=cells[0],
                src_ip=cells[1],
                dest_ip=cells[2],
                port=cells[3],
                proto=cells[4],
                conn=cells[5],
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
    geolocator=None,
    ext_dns_cache=None,
    **kwargs,
):
    # Read existing notes before creating new sheet
    existing_notes = read_existing_notes(wb)
    
    sheet = make_sheet(wb, "Analysis", idx=0)
    sheet.append(
        [
            "Count",
            "Src_IP",
            "Src_Desc",
            "Src_Geo",
            "Dest_IP",
            "Dest_Desc",
            "Dst_Geo",
            "Port",
            "Service",
            "Proto",
            "Conn_State",
            "Notes",
        ]
    )
    
    # Initialize external DNS cache if not provided
    if ext_dns_cache is None:
        ext_dns_cache = {}
    
    # Convert segments list to dict for O(1) lookup (optimization)
    segment_dict = {seg.network: seg for seg in segments}
    
    # Create IP result cache (optimization)
    ip_result_cache = {}
    
    warning_msg("this may take awhile...")
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
        
        handle_service(row, services)
        row.conn = (row.conn, conn_states[row.conn])
        
        # Lookup existing note for this row
        # Key: (src_ip, dest_ip, port, proto, conn_state)
        note_key = (row.src_ip, row.dest_ip, int(row.port), row.proto, row.conn[0])
        row.notes = existing_notes.get(note_key, "")
        
        write_row_to_sheet(row, row_index, sheet)
    
    tab = Table(displayName="AnalysisTable", ref=f"A1:L{len(rows)+1}")
    sheet.add_table(tab)

    # Hide geolocation columns by default (users can unhide in Excel)
    sheet.column_dimensions['D'].hidden = True  # Src_Geo
    sheet.column_dimensions['G'].hidden = True  # Dst_Geo

    # write lookup data to json file for future use
    with open(json_path, "w+") as fp:
        json.dump(dns_data, fp)


def write_row_to_sheet(row, row_index, sheet):
    sheet.cell(row=row_index, column=1, value=int(row.count))

    src_IP = sheet.cell(row=row_index, column=2, value=row.src_ip)
    src_IP.fill = row.src_desc[1][0]
    src_IP.font = row.src_desc[1][1]

    src_Desc = sheet.cell(row=row_index, column=3, value=row.src_desc[0])
    src_Desc.fill = row.src_desc[1][0]
    src_Desc.font = row.src_desc[1][1]

    # Add Src_Geo column
    src_Geo = sheet.cell(row=row_index, column=4, value=row.src_geo)
    src_Geo.fill = row.src_desc[1][0]
    src_Geo.font = row.src_desc[1][1]

    dest_IP = sheet.cell(row=row_index, column=5, value=row.dest_ip)
    dest_IP.fill = row.dest_desc[1][0]
    dest_IP.font = row.dest_desc[1][1]

    dest_Desc = sheet.cell(row=row_index, column=6, value=row.dest_desc[0])
    dest_Desc.fill = row.dest_desc[1][0]
    dest_Desc.font = row.dest_desc[1][1]

    # Add Dst_Geo column
    dst_Geo = sheet.cell(row=row_index, column=7, value=row.dst_geo)
    dst_Geo.fill = row.dest_desc[1][0]
    dst_Geo.font = row.dest_desc[1][1]

    sheet.cell(row=row_index, column=8, value=int(row.port))

    service = sheet.cell(row=row_index, column=9, value=row.service[0])
    service.fill = row.service[1][0]
    service.font = row.service[1][1]

    sheet.cell(row=row_index, column=10, value=row.proto)

    conn_State = sheet.cell(row=row_index, column=11, value=row.conn[0])
    conn_State.fill = row.conn[1][0]
    conn_State.font = row.conn[1][1]

    # Write the note (either existing or empty string)
    sheet.cell(row=row_index, column=12, value=row.notes)


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
    
    desc_to_change = ("Not Triggered IP", IPV6_CELL_COLOR)
    if ip_to_check == str("0.0.0.0"):
        desc_to_change = (
            "Unassigned IPv4",
            IPV6_CELL_COLOR,
        )
    elif ip_to_check == str("255.255.255.255"):
        desc_to_change = (
            "IPv4 All Subnet Broadcast",
            IPV6_CELL_COLOR,
        )
    elif (
        netaddr.valid_ipv6(ip_to_check) or netaddr.IPAddress(ip_to_check).is_multicast()
    ):
        desc_to_change = (
            f"{'IPv6' if netaddr.valid_ipv6(ip_to_check) else 'IPv4'}{'_Multicast' if netaddr.IPAddress(ip_to_check).is_multicast() else ''}",
            IPV6_CELL_COLOR,
        )
    elif (
        netaddr.IPAddress(ip_to_check).is_link_local()
    ):
        desc_to_change = (
            f"{'IPv6' if netaddr.valid_ipv6(ip_to_check) else 'IPv4'}{'_Link-local' if netaddr.IPAddress(ip_to_check).is_link_local() else ''}",
            IPV6_CELL_COLOR,
        )
    elif ip_to_check in segment_dict:
        # O(1) dict lookup
        segment = segment_dict[ip_to_check]
        if ip_to_check in dns_data:
            resolution = dns_data[ip_to_check]
        elif ip_to_check in inventory:
            resolution = inventory[ip_to_check].name
        else:
            resolution = f"Unknown device in {segment.name} network"
            unk_int_IPs.add(ip_to_check)
        if not netaddr.IPAddress(ip_to_check).is_ipv4_private_use():
            resolution = resolution + " {Non-Priv IP}"
        desc_to_change = (
            resolution,
            segment.color,
        )
    elif netaddr.IPAddress(ip_to_check).is_ipv4_private_use():
        if ip_to_check in dns_data:
            desc_to_change = (dns_data[ip_to_check], INTERNAL_NETWORK_CELL_COLOR)
        elif ip_to_check in inventory:
            desc_to_change = (inventory[ip_to_check].name, INTERNAL_NETWORK_CELL_COLOR)
        else:
            desc_to_change = ("Unknown Internal address", INTERNAL_NETWORK_CELL_COLOR)
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
        
        desc_to_change = (resolution, EXTERNAL_NETWORK_CELL_COLOR)
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


def write_externals_sheet(IPs, wb, geolocator=None):
    ext_sheet = make_sheet(wb, "Externals", idx=5)
    ext_sheet.append(["External IP", "Geolocation"])
    for row_index, IP in enumerate(sorted(IPs), start=2):
        # External IP column
        cell = ext_sheet[f"A{row_index}"]
        cell.value = IP
        
        # Geolocation column
        geo_cell = ext_sheet[f"B{row_index}"]
        if geolocator and geolocator.enabled:
            geo_cell.value = geolocator.lookup(IP) or ""
        else:
            geo_cell.value = ""
    
    # Add AutoFilter to columns A and B
    if len(IPs) > 0:
        ext_sheet.auto_filter.ref = f"A1:B{len(IPs)+1}"

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

def write_mac_sheet(mac_df, wb):
    """Fill spreadsheet with MAC address -> IP address translation with manufacturer information"""
    sheet = make_sheet(wb, "MAC", idx=4)
    sheet.append(
        ["MAC", "Manufacturer", "IPs"]
    )
    for index, row in enumerate(mac_df.to_dict(orient="records"), start=2):
        # Source MAC column
        sheet[f"A{index}"].value = row["mac"]

        # Source Manufacturer column
        sheet[f"B{index}"].value = row["vendor"]

        # Source IPs
        sheet[f"C{index}"].value = row["associated_ip"]
        if len(row["associated_ip"]) > 16:
            sel_cell = sheet[f"C{index}"]
            sel_cell.alignment = Alignment(wrap_text=True)
            est_row_hght = int(len(row["associated_ip"])/50)
            if est_row_hght < 1:
                est_row_hght = 1
            sheet.row_dimensions[index].height = est_row_hght * 15

    auto_adjust_width(sheet)
    sheet.column_dimensions["C"].width = 39 * 1.2

def make_sheet(wb, sheet_name, idx=None):
    """Create the sheet if it doesn't already exist otherwise remove it and recreate it"""
    if sheet_name in wb.sheetnames:
        wb.remove(wb[sheet_name])
    return wb.create_sheet(sheet_name, index=idx)


def auto_adjust_width(sheet, width=40):
    """Adjust the width of the columns to fit the data"""
    for col in sheet.columns:
        max_width = max(len(f"{c.value}") for c in col if c.value) + 2
        sheet.column_dimensions[col[0].column_letter].width = (
            width if width < max_width else max_width
        )
