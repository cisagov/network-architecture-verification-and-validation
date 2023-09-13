import io
import os
import shutil
from tempfile import NamedTemporaryFile
from zipfile import ZipFile

import openpyxl

from navv.bll import get_inventory_report_df, get_snmp_df, get_zeek_df
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
    write_inventory_report_sheet,
    write_snmp_sheet,
    write_stats_sheet,
    write_unknown_internals_sheet,
)
from navv.zeek import (
    get_conn_data,
    get_dns_data,
    get_snmp_data,
    run_zeek,
    perform_zeekcut,
)
from navv.utilities import pushd


def generate(customer_name, output_dir, pcap, zeek_logs_zip, spreadsheet):
    """Generate excel sheet."""
    with pushd(output_dir):
        pass

    if spreadsheet and spreadsheet.filename:
        wb = openpyxl.load_workbook(os.path.join(output_dir, spreadsheet.filename))
    else:
        file_name = os.path.join(output_dir, customer_name + "_network_analysis.xlsx")
        wb = get_workbook(file_name)

    # Extract Zeek logs from zip file
    if zeek_logs_zip:
        with ZipFile(f"{output_dir}/{zeek_logs_zip}", "r") as zip_file:
            zip_file.extractall(path=output_dir)
            zeek_logs = os.path.join(output_dir, zeek_logs_zip[:-4])
            os.remove(os.path.join(output_dir, zeek_logs_zip))
    else:
        zeek_logs = os.path.join(output_dir, "logs")

    services, conn_states = get_package_data()
    timer_data = dict()
    segments = get_segments_data(wb["Segments"])
    inventory = get_inventory_data(wb["Inventory Input"])

    if pcap and pcap.filename:
        run_zeek(os.path.join(output_dir, pcap.filename), zeek_logs, timer=timer_data)
    else:
        timer_data["run_zeek"] = "NOT RAN"

    # Get zeek data from conn.log, dns.log and snmp.log
    zeek_data = get_conn_data(zeek_logs)
    snmp_data = get_snmp_data(zeek_logs)
    dns_filtered = get_dns_data(customer_name, output_dir, zeek_logs)

    # Get dns data for resolution
    json_path = os.path.join(output_dir, f"{customer_name}_dns_data.json")

    # Get zeek dataframes
    zeek_df = get_zeek_df(zeek_data, dns_filtered)
    snmp_df = get_snmp_df(snmp_data)

    # Get inventory report dataframe
    inventory_df = get_inventory_report_df(zeek_df)

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
        timer=timer_data,
    )

    write_inventory_report_sheet(inventory_df, wb)

    write_externals_sheet(ext_IPs, wb)

    write_unknown_internals_sheet(unk_int_IPs, wb)

    write_snmp_sheet(snmp_df, wb)

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

    memfile: io.BytesIO
    with NamedTemporaryFile() as tmp:
        wb.save(tmp.name)
        tmp.seek(0)
        memfile = io.BytesIO(tmp.read())

    shutil.rmtree(output_dir)
    return memfile
