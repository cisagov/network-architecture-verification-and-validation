from subprocess import Popen, PIPE, STDOUT, check_call

from navv.message_handler import error_msg
from navv.utilities import pushd, timeit


@timeit
def run_zeek(pcap_path, zeek_logs_path, **kwargs):
    with pushd(zeek_logs_path):
        # can we add Site::local_nets to the zeek call here?
        try:
            check_call(["zeek", "-C", "-r", pcap_path, "local.zeek"])
        except Exception as e:
            error_msg(e)


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
