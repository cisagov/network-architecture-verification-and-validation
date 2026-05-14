import json
import os
import pandas as pd

from navv.utilities import get_mac_vendor, timeit
from navv.validators import is_ipv4_address, is_ipv6_address


MAC_VENDORS_JSON_FILE = os.path.abspath(__file__ + "/../" + "data/mac-vendors.json")


def get_zeek_df(zeek_data: list, dns_data: dict):
    """Return a pandas dataframe of the conn.log data with its dns data."""
    zeek_data = [row.split("\t") for row in zeek_data]
    # Insert dns data to zeek data
    for row in zeek_data:
        row.insert(1, dns_data.get(row[0], ""))
        row.insert(3, dns_data.get(row[2], ""))

    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "src_hostname",
            "dst_ip",
            "dst_hostname",
            "port",
            "proto",
            "conn",
            "src_mac",
            "dst_mac",
        ],
    )



@timeit
def get_snmp_df(zeek_data: list):
    """Return a pandas dataframe of the snmp.log data."""
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "version",
            "community",
        ],
    )

@timeit
def get_mac_df(zeek_df: pd.DataFrame):
    smac_df = zeek_df[
        [
            "src_mac",
            "src_ip",
        ]
    ].reset_index(drop=True)

    dmac_df = zeek_df[
        [
            "dst_mac",
            "dst_ip",
        ]
    ].reset_index(drop=True)

    smac_df = smac_df.rename(columns={'src_mac': 'mac', 'src_ip': 'ip'})
    dmac_df = dmac_df.rename(columns={'dst_mac': 'mac', 'dst_ip': 'ip'})
    mac_df = pd.concat([smac_df, dmac_df], ignore_index=True)
    mac_df = mac_df.groupby('ip')['mac'].apply(lambda x: list(set(x))).reset_index(name='mac')

    def format_macs(macs):
        v_macs = [m for m in macs if m and m != '-']
        if not v_macs:
            return ""
        return ", ".join(str(item) for item in v_macs)

    mac_df["mac"] = mac_df["mac"].apply(format_macs)

    # Source Manufacturer column
    mac_vendors = {}
    with open(MAC_VENDORS_JSON_FILE, encoding="utf-8") as f:
        mac_vendors = json.load(f)
        
    def get_vendors(mac_val):
        if not mac_val: return "Unknown vendor"
        v_list = [get_mac_vendor(mac_vendors, m.strip()) for m in str(mac_val).split(',')]
        v_set = set(v for v in v_list if v != "Unknown vendor")
        if not v_set: return "Unknown vendor"
        return ', '.join(list(v_set))
        
    mac_df["vendor"] = mac_df["mac"].apply(get_vendors)

    return mac_df


@timeit
def get_http_df(zeek_data: list):
    """Return a pandas dataframe of the http.log data."""
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "dst_ip",
            "dst_port",
            "method",
            "host",
            "uri",
            "user_agent",
        ],
    )


@timeit
def get_ssl_df(zeek_data: list):
    """Return a pandas dataframe of the ssl.log data."""
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "dst_ip",
            "dst_port",
            "version",
            "cipher",
            "curve",
            "server_name",
            "resumed",
        ],
    )


@timeit
def get_generic_df(zeek_data: list, columns: list):
    """Return a pandas dataframe for generic logs."""
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(zeek_data, columns=columns)