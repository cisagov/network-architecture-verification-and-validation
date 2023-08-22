#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC
import os
import contextlib
from functools import wraps
from time import monotonic

from tqdm import tqdm

from navv.message_handler import info_msg, success_msg, error_msg
from navv.validators import is_mac_address


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


def timeit(func):
    @wraps(func)
    def _timeit(*args, **kwargs):
        start = monotonic()
        try:
            info_msg(f"running {func.__name__}")
            return func(*args, **kwargs)
        finally:
            end = monotonic()
            success_msg(f"{func.__name__} execution time:\n{end - start:0.2f} seconds")

    return _timeit


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


def get_mac_vendor(mac_vendors: dict, mac_address: str) -> str:
    """Return the vendor of the MAC address."""
    mac_address = mac_address.upper()

    if not is_mac_address(mac_address):
        error_msg(f"Invalid MAC address: {mac_address}")
        return f"Bad MAC address {mac_address}"

    try:
        vendor = [
            vendor["vendorName"]
            for vendor in mac_vendors
            if mac_address.startswith(vendor["macPrefix"])
        ][0]
    except IndexError:
        error_msg(f"Unknown vendor for MAC address: {mac_address}")
        return "Unknown Vendor"

    return vendor
