#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

import os
import itertools
from collections import Counter
import socket
from copy import copy
import pkg_resources
import pickle
import string
import json

import openpyxl
import openpyxl.styles
from openpyxl.worksheet.table import Table
import netaddr
from tqdm import tqdm

from navv import data_types
from navv import utilities
from navv.utils.tools import get_mac_vendor

DATA_PKL_FILE = pkg_resources.resource_filename(__name__, "data/data.pkl")

COL_NAMES = [
    "Count",
    "Src_IP",
    "Src_Desc",
    "Dest_IP",
    "Dest_Desc",
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


def get_workbook(file_name):
    """Create the blank Inventory and Segment sheets for data input into the tool"""
    if os.path.isfile(file_name):
        wb = openpyxl.load_workbook(file_name)
    else:
        wb = openpyxl.Workbook()
        seg_sheet = wb.create_sheet("Segments")

        seg_sheet.cell(row=1, column=1, value="Name").style = HEADER_STYLE
        seg_sheet.cell(row=1, column=2, value="Description").style = HEADER_STYLE
        seg_sheet.cell(row=1, column=3, value="CIDR").style = HEADER_STYLE
    return wb


@utilities.timeit
def get_inventory_data(ws, **kwargs):
    inventory = dict()
    for row in itertools.islice(ws.iter_rows(), 1, None):
        if not row[0].value or not row[1].value:
            continue
        inventory[row[0].value] = data_types.InventoryItem(
            ip=row[0].value,
            name=row[1].value,
            color=(copy(row[0].fill), copy(row[0].font)),
        )
    return inventory


@utilities.timeit
def get_segments_data(ws):
    segments = list()
    for row in itertools.islice(ws.iter_rows(), 1, None):
        if not row[2].value:
            continue
        segments.append(
            data_types.Segment(
                name=row[0].value,
                description=row[1].value,
                network=row[2].value,
                color=[copy(row[0].fill), copy(row[0].font)],
            )
        )
    all_ips = []
    for segment in segments:
        all_ips = all_ips + segment.network
    segments.append(all_ips)
    return segments


def get_package_data():
    """Load services and conn_states data into memory"""
    with open(DATA_PKL_FILE, "rb") as f:
        services, conn_states = pickle.load(f)
    return services, conn_states


@utilities.timeit
def create_analysis_array(sort_input, **kwargs):
    arr = list()
    mac_dict = dict()
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
        if cells[6] is not None and cells[6] != "":
            if netaddr.IPAddress(cells[1]).is_private():
                if cells[6] not in mac_dict:
                    mac_dict[cells[6]] = [cells[1]]
                else:
                    if cells[1] not in mac_dict[cells[6]]:
                        mac_dict[cells[6]].append(cells[1])

    return arr, mac_dict


@utilities.timeit
def perform_analysis(
    wb,
    rows,
    services,
    conn_states,
    segments,
    dns_data,
    json_path,
    ext_IPs,
    unk_int_IPs,
    **kwargs,
):
    sheet = make_sheet(wb, "Analysis", idx=0)
    sheet.append(
        [
            "Count",
            "Src_IP",
            "Src_Desc",
            "Dest_IP",
            "Dest_Desc",
            "Port",
            "Service",
            "Proto",
            "Conn_State",
            "Notes",
        ]
    )
    print("Performing analysis(including lookups). This may take a while:")
    for row_index, row in enumerate(tqdm(rows), start=2):
        row.src_desc = handle_ip(row.src_ip, dns_data, segments, ext_IPs, unk_int_IPs)
        row.dest_desc = handle_ip(row.dest_ip, dns_data, segments, ext_IPs, unk_int_IPs)
        handle_service(row, services)
        row.conn = (row.conn, conn_states[row.conn])
        write_row_to_sheet(row, row_index, sheet)
    tab = Table(displayName="AnalysisTable", ref=f"A1:J{len(rows)+1}")
    sheet.add_table(tab)
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

    dest_IP = sheet.cell(row=row_index, column=4, value=row.dest_ip)
    dest_IP.fill = row.dest_desc[1][0]
    dest_IP.font = row.dest_desc[1][1]

    dest_Desc = sheet.cell(row=row_index, column=5, value=row.dest_desc[0])
    dest_Desc.fill = row.dest_desc[1][0]
    dest_Desc.font = row.dest_desc[1][1]

    sheet.cell(row=row_index, column=6, value=int(row.port))

    service = sheet.cell(row=row_index, column=7, value=row.service[0])
    service.fill = row.service[1][0]
    service.font = row.service[1][1]

    sheet.cell(row=row_index, column=8, value=row.proto)

    conn_State = sheet.cell(row=row_index, column=9, value=row.conn[0])
    conn_State.fill = row.conn[1][0]
    conn_State.font = row.conn[1][1]

    # placeholder for notes cell
    sheet.cell(row=row_index, column=10, value="")


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


def handle_ip(ip_to_check, dns_data, segments, ext_IPs, unk_int_IPs):
    """Function take IP Address and uses collected dns_data, inventory, and segment information to give IP Addresses in analysis context.

    Priority flow:
        * DHCP Broadcasting
        * Multicast
        * Within Segments identified
        * Within Inventory, not within an Identified Segment
        * Private Network
        * External (Public IP space) or Internet

    This will capture the name description and the color coding identified within the worksheet.
    """
    #
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
            f"{'IPV6' if netaddr.valid_ipv6(ip_to_check) else 'IPV4'}{'_Multicast' if netaddr.IPAddress(ip_to_check).is_multicast() else ''}",
            IPV6_CELL_COLOR,
        )
    elif ip_to_check in segments[len(segments) - 1]:
        for segment in segments[:-1]:
            if ip_to_check not in segment.network:
                continue
            if ip_to_check in dns_data:
                desc_to_change = (dns_data[ip_to_check], segment.color)
            else:
                desc_to_change = (
                    f"Unknown device in {segment.name} network",
                    segment.color,
                )
                unk_int_IPs.add(ip_to_check)
    elif netaddr.IPAddress(ip_to_check).is_private():
        if ip_to_check in dns_data:
            desc_to_change = (dns_data[ip_to_check], INTERNAL_NETWORK_CELL_COLOR)
        else:
            desc_to_change = ("Unknown Internal address", INTERNAL_NETWORK_CELL_COLOR)
            unk_int_IPs.add(ip_to_check)
    else:
        ext_IPs.add(ip_to_check)
        if ip_to_check in dns_data:
            resolution = dns_data[ip_to_check]
        else:
            try:
                resolution = socket.gethostbyaddr(ip_to_check)[0]
            except socket.herror:
                resolution = "Unresolved external address"
                ALREADY_UNRESOLVED.append(ip_to_check)
            finally:
                dns_data[ip_to_check] = resolution
        desc_to_change = (resolution, EXTERNAL_NETWORK_CELL_COLOR)
    return desc_to_change


def write_inventory_report_sheet(
    wb,
    data,
):
    """Create the Inventory Report sheet."""
    sheet = make_sheet(wb, "Inventory Report", idx=0)

    # write header
    sheet.append(
        [
            "IP",
            "Name",
            "MAC Address",
            "Vendor",
        ]
    )

    # write data
    for row_index, row in enumerate(data, start=2):
        row = row.split("\t")

        # IP Address
        sheet.cell(row=row_index, column=1, value=row[0])

        # Name
        sheet.cell(row=row_index, column=2, value="Name")

        # MAC Address
        sheet.cell(row=row_index, column=3, value=row[5])

        # Vendor
        sheet.cell(row=row_index, column=4, value=get_mac_vendor(row[5]))


def write_conn_states_sheet(conn_states, wb):
    new_ws = make_sheet(wb, "Conn_States", idx=8)
    new_ws.append(["State", "Description"])
    for row_num, conn_state in enumerate(conn_states, start=2):
        state_cell = new_ws[f"A{row_num}"]
        desc_cell = new_ws[f"B{row_num}"]
        state_cell.value = conn_state
        state_cell.fill = conn_states[conn_state][0]
        state_cell.font = conn_states[conn_state][1]
        desc_cell.value = conn_states[conn_state][2]
        desc_cell.fill = conn_states[conn_state][0]
        desc_cell.font = conn_states[conn_state][1]
    auto_adjust_width(new_ws)


def write_macs_sheet(mac_dict, wb):
    """Fill spreadsheet with MAC address -> IP address translation with manufacturer information"""
    macs_sheet = make_sheet(wb, "MACs", idx=4)
    macs_sheet.append(["MAC", "Manufacturer", "IPs"])
    for row_index, mac in enumerate(mac_dict, start=2):
        macs_sheet[f"A{row_index}"].value = mac
        try:
            eui = netaddr.EUI(mac)
            oui = eui.oui
            orgs = [oui.registration(i).org for i in range(oui.reg_count)]
        except netaddr.core.NotRegisteredError:
            orgs = ["Not a registered manufacturer"]
        except netaddr.core.AddrFormatError:
            orgs = [f"Bad MAC address {mac}"]
        except Exception:
            orgs = ["Unspecified MAC error"]
        macs_sheet[f"B{row_index}"].value = "\n".join(orgs)
        ip_list_cell = macs_sheet[f"C{row_index}"]
        ip_list_cell.alignment = openpyxl.styles.Alignment(wrap_text=True)
        num_ips = len(mac_dict[mac])
        if num_ips > 10:
            display_list = mac_dict[mac][:10]
            display_list.append(f"Displaying 10 IPs of {num_ips}")
            ip_list_cell.value = "\n".join(display_list)
        else:
            ip_list_cell.value = "\n".join(mac_dict[mac][:10])
        macs_sheet.row_dimensions[row_index].height = min(num_ips, 11) * 15
        if row_index % 2 == 0:
            for cell in macs_sheet[f"{row_index}:{row_index}"]:
                cell.fill = openpyxl.styles.PatternFill("solid", fgColor="AAAAAA")
    auto_adjust_width(macs_sheet)
    macs_sheet.column_dimensions["C"].width = 39 * 1.2


def write_externals_sheet(IPs, wb):
    ext_sheet = make_sheet(wb, "Externals", idx=5)
    ext_sheet.append(["External IP"])
    for row_index, IP in enumerate(sorted(IPs), start=2):
        cell = ext_sheet[f"A{row_index}"]
        cell.value = IP
        if row_index % 2 == 0:
            cell.fill = openpyxl.styles.PatternFill("solid", fgColor="AAAAAA")
    auto_adjust_width(ext_sheet)


def write_unknown_internals_sheet(IPs, wb):
    int_sheet = make_sheet(wb, "Unkown_Internals", idx=6)
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


def make_sheet(wb, sheet_name, idx=None):
    """Create the sheet if it doesn't already exist otherwise remove it and recreate it"""
    if sheet_name in wb.sheetnames:
        wb.remove(wb[sheet_name])
    return wb.create_sheet(sheet_name, index=idx)


def auto_adjust_width(sheet):
    factor = 1.7
    for col in sheet.columns:
        vals = (len("{}".format(c.value)) for c in col if c.value is not None)
        max_width = max(vals) * factor
        sheet.column_dimensions[col[0].column_letter].width = (
            max_width if max_width < 20 else max_width * 1.2 / 1.7
        )
