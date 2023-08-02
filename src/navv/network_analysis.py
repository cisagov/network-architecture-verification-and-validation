#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

# python std library imports
import argparse
import json
import os
import pkg_resources
import sys

# package imports
from navv import utilities
from navv.spreadsheet_tools import (
    auto_adjust_width,
    create_analysis_array,
    get_workbook,
    get_segments_data,
    get_inventory_data,
    get_package_data,
    perform_analysis,
    write_conn_states_sheet,
    write_externals_sheet,
    write_inventory_report_sheet,
    write_macs_sheet,
    write_stats_sheet,
    write_unknown_internals_sheet,
)

from navv._version import __version__

DATA_PATH = pkg_resources.resource_filename("navv", "data/")


def parse_args():
    parser = argparse.ArgumentParser(
        description=f"NAVV: Network Architecture Verification and Validation {__version__}"
    )
    parser.add_argument("customer_name", help="Name of the customer")
    parser.add_argument(
        "-o",
        "--output-dir",
        help="Directory to place resultant analysis files in. Defaults to current working directory.",
        default=os.getcwd(),
    )
    parser.add_argument(
        "-p",
        "--pcap",
        help="Path to pcap file. NAVV requires zeek logs or pcap. If used, zeek will run on pcap to create new logs.",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Display NAVV version",
        dest="show_version",
        action="store_true",
    )
    parser.add_argument(
        "-z",
        "--zeek-logs",
        help="Path to store or contain zeek log files. Defaults to current working directory.",
        default=os.getcwd(),
    )
    return parser.parse_args()


@utilities.timeit
def main(args):
    """Main function for performing zeek-cut commands and sorting the output"""

    if args.show_version:
        print(f"{__version__}")
        sys.exit(0)

    out_dir = args.output_dir
    with utilities.pushd(out_dir):
        pass
    file_name = os.path.join(out_dir, args.customer_name + "_network_analysis.xlsx")

    wb = get_workbook(file_name)

    services, conn_states = get_package_data()
    timer_data = dict()
    segments = get_segments_data(wb["Segments"])
    zeek_logs_path = args.zeek_logs

    if args.pcap:
        utilities.run_zeek(os.path.abspath(args.pcap), zeek_logs_path, timer=timer_data)
    else:
        timer_data["run_zeek"] = "NOT RAN"
    zeek_data = (
        utilities.perform_zeekcut(
            fields=[
                "id.orig_h",
                "id.resp_h",
                "id.resp_p",
                "proto",
                "conn_state",
                "orig_l2_addr",
                "resp_l2_addr",
            ],
            log_file=os.path.join(zeek_logs_path, "conn.log"),
        )
        .decode("utf-8")
        .split("\n")[:-1]
    )
    # turn zeekcut data into rows for spreadsheet
    rows, mac_dict = create_analysis_array(zeek_data, timer=timer_data)

    # get dns data for resolution
    json_path = os.path.join(out_dir, f"{args.customer_name}_dns_data.json")

    if os.path.exists(json_path):
        with open(json_path, "rb") as json_file:
            dns_filtered = json.load(json_file)
    else:
        dns_data = utilities.perform_zeekcut(
            fields=["query", "answers", "qtype", "rcode_name"],
            log_file=os.path.join(zeek_logs_path, "dns.log"),
        )
        dns_filtered = utilities.trim_dns_data(dns_data)

    ext_IPs = set()
    unk_int_IPs = set()
    perform_analysis(
        wb,
        rows,
        services,
        conn_states,
        segments,
        dns_filtered,
        json_path,
        ext_IPs,
        unk_int_IPs,
        timer=timer_data,
    )

    auto_adjust_width(wb["Analysis"])

    write_inventory_report_sheet(
        wb,
        zeek_data,
    )

    write_macs_sheet(mac_dict, wb)

    write_externals_sheet(ext_IPs, wb)

    write_unknown_internals_sheet(unk_int_IPs, wb)

    times = (
        utilities.perform_zeekcut(
            fields=["ts"], log_file=os.path.join(zeek_logs_path, "conn.log")
        )
        .decode("utf-8")
        .split("\n")[:-1]
    )
    forward = sorted(times)
    start = float(forward[0])
    end = float(forward[len(forward) - 1])
    cap_time = end - start
    timer_data[
        "Length of Capture time"
    ] = "{} day(s) {} hour(s) {} minutes {} seconds".format(
        int(cap_time / 86400),
        int(cap_time % 86400 / 3600),
        int(cap_time % 3600 / 60),
        int(cap_time % 60),
    )
    write_stats_sheet(wb, timer_data)
    write_conn_states_sheet(conn_states, wb)

    wb.save(file_name)


if __name__ == "__main__":
    main(parse_args())
