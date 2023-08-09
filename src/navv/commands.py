"""CLI Commands."""
import json
import os
import webbrowser


# Third-Party Libraries
import click

# cisagov Libraries
from navv.gui import app
from navv.message_handler import success_msg, warning_msg
from navv import spreadsheet_tools
from navv.utilities import pushd, run_zeek, perform_zeekcut, trim_dns_data


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
@click.argument("customer_name")
def generate(customer_name, output_dir, pcap, zeek_logs):
    """Generate excel sheet."""
    with pushd(output_dir):
        pass
    file_name = os.path.join(output_dir, customer_name + "_network_analysis.xlsx")

    wb = spreadsheet_tools.get_workbook(file_name)

    services, conn_states = spreadsheet_tools.get_package_data()
    timer_data = dict()
    segments = spreadsheet_tools.get_segments_data(wb["Segments"])
    inventory = spreadsheet_tools.get_inventory_data(wb["Inventory Input"])

    if pcap:
        run_zeek(os.path.abspath(pcap), zeek_logs, timer=timer_data)
    else:
        timer_data["run_zeek"] = "NOT RAN"
    zeek_data = (
        perform_zeekcut(
            fields=[
                "id.orig_h",
                "id.resp_h",
                "id.resp_p",
                "proto",
                "conn_state",
                "orig_l2_addr",
                "resp_l2_addr",
            ],
            log_file=os.path.join(zeek_logs, "conn.log"),
        )
        .decode("utf-8")
        .split("\n")[:-1]
    )

    # turn zeekcut data into rows for spreadsheet
    rows, mac_dict = spreadsheet_tools.create_analysis_array(
        zeek_data, timer=timer_data
    )

    # get dns data for resolution
    json_path = os.path.join(output_dir, f"{customer_name}_dns_data.json")

    if os.path.exists(json_path):
        with open(json_path, "rb") as json_file:
            dns_filtered = json.load(json_file)
    else:
        dns_data = perform_zeekcut(
            fields=["query", "answers", "qtype", "rcode_name"],
            log_file=os.path.join(zeek_logs, "dns.log"),
        )
        dns_filtered = trim_dns_data(dns_data)

    ext_IPs = set()
    unk_int_IPs = set()
    spreadsheet_tools.perform_analysis(
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
        timer=timer_data,
    )

    spreadsheet_tools.write_inventory_report_sheet(mac_dict, wb)

    spreadsheet_tools.write_macs_sheet(mac_dict, wb)

    spreadsheet_tools.write_externals_sheet(ext_IPs, wb)

    spreadsheet_tools.write_unknown_internals_sheet(unk_int_IPs, wb)

    spreadsheet_tools.auto_adjust_width(wb["Analysis"])

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
    spreadsheet_tools.write_stats_sheet(wb, timer_data)
    spreadsheet_tools.write_conn_states_sheet(conn_states, wb)

    wb.save(file_name)

    if pcap:
        success_msg(f"Successfully created file: {file_name}")


@click.command("launch")
def launch():
    """Launch the NAVV GUI."""
    port = 5000
    warning_msg("Launching GUI in browser...")
    webbrowser.open(f"http://127.0.0.1:{port}/")
    app.run(port=port)
