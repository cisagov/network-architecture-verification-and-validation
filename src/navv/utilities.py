#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

import os
import contextlib
from subprocess import Popen, PIPE, STDOUT, check_call
import time
from tqdm import tqdm


@contextlib.contextmanager
def pushd(new_dir):
    previous_dir = os.getcwd()
    if not os.path.isdir(new_dir):
        os.makedirs(new_dir)
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)


def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        td = time.time() - ts
        time_elapsed = f"{method.__name__}:\n\tHours: {int(int(td / 3600) % 24)}\n\tMinutes: {int(int(td / 60) % 60)}\n\tSeconds: {int(td % 60)}"
        if "timer" in kw:
            kw["timer"][
                method.__name__
            ] = f"{int(td/86400)} day(s) {int(td%86400/3600)} hour(s) {int(td%3600/60)} minutes {int(td%60)} seconds"
        print(time_elapsed)
        return result

    return timed


@timeit
def run_zeek(pcap_path, zeek_logs_path, **kwargs):
    with pushd(zeek_logs_path):
        # can we add Site::local_nets to the zeek call here?
        err = check_call(["zeek", "-C", "-r", pcap_path, "local.zeek"])
        print(f"Zeek returned with code: {err}")


def perform_zeekcut(fields, log_file):
    """Perform the call to zeek-cut with the identified fields on the specified log file"""
    try:
        with open(log_file, "rb") as f:
            zeekcut = Popen(["zeek-cut"] + fields, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
            return zeekcut.communicate(input=f.read())[0]
    except OSError as e:
        # probably "file does not exist"
        return b""


def trim_dns_data(data):
    """Find entries in dns log that contain no_error and return a dict of {ip: hostname,}"""
    ret_data = {}
    # log_list = log_to_list(data)
    print("Trimming DNS.log data:")
    for row in tqdm(data.decode("utf-8 ").split("\n")[:-1]):
        # line_data = list(stream(row, '\t'))
        line_data = row.split("\t")
        if line_data[2] == "1" and line_data[3] == "NOERROR":
            for split in line_data[1].split(","):
                ret_data[split] = line_data[0]
    return ret_data
