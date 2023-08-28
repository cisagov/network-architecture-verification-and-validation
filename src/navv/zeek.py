import json
import os
from subprocess import Popen, PIPE, STDOUT, check_call

from navv.message_handler import error_msg
from navv.utilities import pushd, timeit, trim_dns_data


@timeit
def run_zeek(pcap_path, zeek_logs_path, **kwargs):
    with pushd(zeek_logs_path):
        # can we add Site::local_nets to the zeek call here?
        try:
            check_call(["zeek", "-C", "-r", pcap_path, "local.zeek"])
        except Exception as e:
            error_msg(e)


@timeit
def get_dns_data(customer_name, output_dir, zeek_logs):
    """Get DNS data from zeek logs or from a json file if it exists"""
    json_path = os.path.join(output_dir, f"{customer_name}_dns_data.json")
    if os.path.exists(json_path):
        with open(json_path, "rb") as json_file:
            return json.load(json_file)

    dns_data = perform_zeekcut(
        fields=["query", "answers", "qtype", "rcode_name"],
        log_file=os.path.join(zeek_logs, "dns.log"),
    )
    return trim_dns_data(dns_data)


def perform_zeekcut(fields, log_file):
    """Perform the call to zeek-cut with the identified fields on the specified log file"""
    try:
        with open(log_file, "rb") as f:
            zeekcut = Popen(
                ["zeek-cut"] + fields, stdout=PIPE, stdin=PIPE, stderr=STDOUT
            )
            return zeekcut.communicate(input=f.read())[0]
    except OSError as e:
        # probably "file does not exist"
        return b""
