import json
import os
from subprocess import Popen, PIPE, STDOUT, check_call

from navv.message_handler import error_msg
from navv.utilities import pushd, timeit, trim_dns_data


@timeit
def get_conn_data(zeek_logs):
    """Return a list of Zeek conn.log data."""
    return (
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


@timeit
def get_dns_data(customer_name, output_dir, zeek_logs):
    """Get DNS data from zeek logs or from a json file if it exists"""
    json_path = os.path.join(output_dir, f"{customer_name}_dns_data.json")
    if os.path.exists(json_path):
        with open(json_path, "rb") as json_file:
            try:
                return json.load(json_file)
            except:
                pass

    dns_data = perform_zeekcut(
        fields=["query", "answers", "qtype", "rcode_name"],
        log_file=os.path.join(zeek_logs, "dns.log"),
    )
    return trim_dns_data(dns_data)


@timeit
def get_snmp_data(zeek_logs):
    """Get SNMP data from zeek logs or from a json file if it exists"""
    return (
        perform_zeekcut(
            fields=[
                "id.orig_h",
                "id.orig_p",
                "id.resp_h",
                "id.resp_p",
                "version",
                "community",
            ],
            log_file=os.path.join(zeek_logs, "snmp.log"),
        )
        .decode("utf-8")
        .split("\n")[:-1]
    )

@timeit
def get_dhcp_data(zeek_logs):
    """Get DHCP data for hostname resolution"""
    dhcp_data = perform_zeekcut(
        fields=["client_addr", "host_name"],
        log_file=os.path.join(zeek_logs, "dhcp.log"),
    )
    ip_to_host = {}
    if dhcp_data:
        rows = dhcp_data.decode("utf-8").strip().split("\n")
        for row in rows:
            if not row or row.startswith("#"): continue
            parts = row.split("\t")
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                if ip and hostname and hostname != "-" and ip != "-":
                    ip_to_host[ip] = hostname
    return ip_to_host


@timeit
def get_http_data(zeek_logs):
    """Return list of HTTP log data."""
    return perform_zeekcut(
        fields=["id.orig_h", "id.resp_h", "id.resp_p", "method", "host", "uri", "user_agent"],
        log_file=os.path.join(zeek_logs, "http.log")
    ).decode("utf-8").split("\n")[:-1]


@timeit
def get_ssl_data(zeek_logs):
    """Return list of SSL log data."""
    return perform_zeekcut(
        fields=["id.orig_h", "id.resp_h", "id.resp_p", "version", "cipher", "curve", "server_name", "resumed"],
        log_file=os.path.join(zeek_logs, "ssl.log")
    ).decode("utf-8").split("\n")[:-1]


@timeit
def get_log_data(zeek_logs, log_name, fields):
    """Generic log extraction function."""
    return perform_zeekcut(
        fields=fields,
        log_file=os.path.join(zeek_logs, f"{log_name}.log")
    ).decode("utf-8").split("\n")[:-1]



def perform_zeekcut(fields, log_file):
    """Perform the call to zeek-cut with the identified fields on the specified log file"""
    try:
        with open(log_file, "rb") as f:
            zeekcut = Popen(
                ["zeek-cut"] + fields, stdin=f, stdout=PIPE, stderr=STDOUT
            )
            return zeekcut.communicate()[0]
    except OSError as e:
        # probably "file does not exist"
        return b""


@timeit
def run_zeek(pcap_path, zeek_logs_path, **kwargs):
    with pushd(zeek_logs_path):
        # can we add Site::local_nets to the zeek call here?
        try:
            check_call(["zeek", "-C", "-r", pcap_path, "local.zeek"])
        except Exception as e:
            error_msg(e)
