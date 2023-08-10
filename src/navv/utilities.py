#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

import os
import contextlib
import json
import time

from netaddr import EUI, core as netaddr_core
from tqdm import tqdm

from navv.message_handler import info_msg, error_msg


MAC_VENDORS_JSON_FILE = os.path.abspath(__file__ + "/../" + "data/mac-vendors.json")


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
        info_msg(time_elapsed)
        return result

    return timed


def trim_dns_data(data):
    """Find entries in dns log that contain no_error and return a dict of {ip: hostname,}"""
    ret_data = {}
    # log_list = log_to_list(data)
    info_msg("Trimming DNS.log data:")
    for row in tqdm(data.decode("utf-8 ").split("\n")[:-1]):
        # line_data = list(stream(row, '\t'))
        line_data = row.split("\t")
        if line_data[2] == "1" and line_data[3] == "NOERROR":
            for split in line_data[1].split(","):
                ret_data[split] = line_data[0]
    return ret_data


def get_mac_vendor(mac_address: str) -> str:
    """Return the vendor of the MAC address."""
    mac_address = mac_address.upper()

    try:
        EUI(mac_address)
    except netaddr_core.AddrFormatError:
        error_msg(f"Invalid MAC address: {mac_address}")
        return f"Bad MAC address {mac_address}"

    with open(MAC_VENDORS_JSON_FILE) as f:
        mac_vendors = json.load(f)

    try:
        vendor = [
            vendor["vendorName"]
            for vendor in mac_vendors
            if mac_address.startswith(vendor["macPrefix"])
        ][0]
    except IndexError:
        vendor = ""

    if not vendor:
        error_msg(f"Unknown vendor for MAC address: {mac_address}")
        return "Unknown Vendor"

    return vendor
