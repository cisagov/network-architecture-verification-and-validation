import glob
import json
import os
import re
import subprocess
from subprocess import Popen, PIPE, STDOUT, check_call

from navv.message_handler import error_msg, warning_msg, success_msg
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


def find_local_zeek():
    """Locate the system local.zeek configuration file."""
    # Try using zeek-config site_dir
    try:
        site_dir = subprocess.check_output(["zeek-config", "--site_dir"], stderr=subprocess.DEVNULL).decode("utf-8").strip()
        local_zeek = os.path.join(site_dir, "local.zeek")
        if os.path.exists(local_zeek):
            return local_zeek
    except Exception:
        pass

    # Common default paths for WSL, Linux, macOS
    common_paths = [
        "/opt/homebrew/share/zeek/site/local.zeek",
        "/opt/homebrew/Cellar/zeek/*/share/zeek/site/local.zeek",
        "/usr/local/share/zeek/site/local.zeek",
        "/usr/share/zeek/site/local.zeek",
        "/usr/local/zeek/share/zeek/site/local.zeek",
        "/opt/zeek/share/zeek/site/local.zeek",
    ]
    for path_pattern in common_paths:
        for path in glob.glob(path_pattern):
            if os.path.exists(path):
                return path
    return None


def check_and_enable_zeek_policies():
    """Verify if mac-logging and vlan-logging are enabled in local.zeek, and attempt to enable them."""
    local_zeek = find_local_zeek()
    if not local_zeek:
        warning_msg("Could not locate local.zeek configuration file. Unable to verify mac_logging and VLAN tagging status.")
        return

    try:
        with open(local_zeek, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        warning_msg(f"Could not read local.zeek at {local_zeek}: {e}")
        return

    mac_logging_pattern = re.compile(r'^\s*#?\s*@load\s+policy/protocols/conn/mac-logging\b', re.MULTILINE)
    vlan_logging_pattern = re.compile(r'^\s*#?\s*@load\s+policy/protocols/conn/vlan-logging\b', re.MULTILINE)

    modified = False
    new_content = content

    def enable_policy(policy_name, pattern, current_content):
        match = pattern.search(current_content)
        if not match:
            warning_msg(f"Zeek policy '{policy_name}' is not enabled in local.zeek. Attempting to enable it for you...")
            return current_content + f"\n@load policy/protocols/conn/{policy_name}\n", True

        line = match.group(0)
        if line.strip().startswith('#'):
            warning_msg(f"Zeek policy '{policy_name}' is not enabled in local.zeek. Attempting to enable it for you...")
            uncommented_line = re.sub(r'^\s*#\s*', '', line)
            new_content = current_content.replace(line, uncommented_line)
            return new_content, True
        else:
            return current_content, False

    new_content, mac_updated = enable_policy("mac-logging", mac_logging_pattern, new_content)
    new_content, vlan_updated = enable_policy("vlan-logging", vlan_logging_pattern, new_content)

    if mac_updated or vlan_updated:
        try:
            with open(local_zeek, "w", encoding="utf-8") as f:
                f.write(new_content)
            success_msg(f"Successfully enabled required policies in local.zeek at {local_zeek}")
        except PermissionError:
            warning_msg(
                f"Permission denied: Unable to modify local.zeek at {local_zeek}.\n"
                f"Please enable mac-logging and vlan-logging manually by uncommenting the corresponding lines in {local_zeek}."
            )
        except Exception as e:
            warning_msg(f"Failed to write to local.zeek: {e}")


@timeit
def run_zeek(pcap_path, zeek_logs_path, **kwargs):
    check_and_enable_zeek_policies()
    with pushd(zeek_logs_path):
        # can we add Site::local_nets to the zeek call here?
        try:
            check_call(["zeek", "-C", "-r", pcap_path, "local.zeek"])
        except Exception as e:
            error_msg(str(e))
            raise

