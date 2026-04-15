"""CLI Commands."""
import os
import webbrowser
import json


# Third-Party Libraries
import click

# cisagov Libraries
from navv.gui.app import app
from navv.bll import get_snmp_df, get_zeek_df, get_mac_df
from navv.message_handler import success_msg, warning_msg
from navv.spreadsheet_tools import (
    auto_adjust_width,
    create_analysis_array,
    get_inventory_data,
    get_package_data,
    get_segments_data,
    get_workbook,
    perform_analysis,
    write_conn_states_sheet,
    write_externals_sheet,
    write_snmp_sheet,
    write_stats_sheet,
    write_unknown_internals_sheet,
    write_mac_sheet,
)
from navv.zeek import (
    get_conn_data,
    get_dns_data,
    get_snmp_data,
    run_zeek,
    perform_zeekcut,
)
from navv.utilities import pushd
from navv.geolocation import Geolocator


@click.command("generate")
@click.option(
    "-o",
    "--output-dir",
    required=False,
    help="Directory to place resultant analysis files in. Defaults to current working directory.",
    type=str,
)
@click.option(
    "-p",
    "--pcap",
    required=False,
    help="Path to pcap file. NAVV requires zeek logs or pcap. If used, zeek will run on pcap to create new logs.",
    type=str,
)
@click.option(
    "-z",
    "--zeek-logs",
    required=False,
    help="Path to store or contain zeek log files. Defaults to current working directory.",
    type=str,
)
@click.option(
    "-g",
    "--geoip-db",
    required=False,
    help="Path to GeoLite2 Country database file (MMDB format). If not specified, searches common locations.",
    type=str,
)
@click.argument("customer_name")
def generate(customer_name, output_dir, pcap, zeek_logs, geoip_db):
    """Generate excel sheet."""
    with pushd(output_dir):
        pass
    file_name = os.path.join(output_dir, customer_name + "_network_analysis.xlsx")

    wb = get_workbook(file_name)

    # Initialize geolocator for IP geolocation
    geolocator = Geolocator(db_path=geoip_db)

    services, conn_states = get_package_data()
    timer_data = dict()
    segments = get_segments_data(wb["Segments"])
    inventory = get_inventory_data(wb["Inventory Input"])

    if pcap:
        run_zeek(os.path.abspath(pcap), zeek_logs, timer=timer_data)
    else:
        timer_data["run_zeek"] = "NOT RAN"

    # Get zeek data from conn.log, dns.log and snmp.log
    zeek_data = get_conn_data(zeek_logs)
    snmp_data = get_snmp_data(zeek_logs)
    dns_filtered = get_dns_data(customer_name, output_dir, zeek_logs)

    # Get dns data for resolution
    json_path = os.path.join(output_dir, f"{customer_name}_dns_data.json")
    
    # Get external DNS cache (similar to dns_data pattern)
    ext_dns_path = os.path.join(output_dir, f"{customer_name}_ext_dns_cache.json")
    if os.path.exists(ext_dns_path):
        with open(ext_dns_path, "r") as f:
            try:
                ext_dns_cache = json.load(f)
            except:
                ext_dns_cache = {}
    else:
        ext_dns_cache = {}

    # Get zeek dataframes
    zeek_df = get_zeek_df(zeek_data, dns_filtered)
    snmp_df = get_snmp_df(snmp_data)

    # Get mac dataframe
    mac_df = get_mac_df(zeek_df)

    # Turn zeekcut data into rows for spreadsheet
    rows = create_analysis_array(zeek_data, timer=timer_data)

    ext_IPs = set()
    unk_int_IPs = set()
    perform_analysis(
        wb,
        rows,
        services,
        conn_states,
        inventory,
        segments,
        dns_filtered,
        json_path,
        ext_IPs,
        unk_int_IPs,
        geolocator=geolocator,
        ext_dns_cache=ext_dns_cache,
        timer=timer_data,
    )

    write_externals_sheet(ext_IPs, wb, geolocator=geolocator)

    write_unknown_internals_sheet(unk_int_IPs, wb)

    write_snmp_sheet(snmp_df, wb)

    write_mac_sheet(mac_df, wb)

    auto_adjust_width(wb["Analysis"])

    times = (
        perform_zeekcut(fields=["ts"], log_file=os.path.join(zeek_logs, "conn.log"))
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
    
    # Save external DNS cache for future runs
    with open(ext_dns_path, "w") as f:
        json.dump(ext_dns_cache, f)
    
    # Close geolocator to free resources
    geolocator.close()

    if pcap:
        success_msg(f"Successfully created file: {file_name}")


@click.command("launch")
def launch():
    """Launch the NAVV GUI."""
    port = 5000
    warning_msg("Launching GUI in browser...")
    webbrowser.open(f"http://127.0.0.1:{port}/")
    app.run(port=port)
