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
    mac_df = smac_df._append(dmac_df, ignore_index=True)
    mac_df = mac_df.groupby('mac')['ip'].apply(list).reset_index(name='associated_ip')

    for index, row in enumerate(mac_df.to_dict(orient="records"), start=0):
        # Source IPs - Need to get unique values
        ips = set(row["associated_ip"])
        list_ips = (list(ips))
        if len(list_ips) > 1:
            ip_list = ', '.join([str(item) for item in list_ips])

        else:
            ip_list = list_ips[0]

        mac_df.at[index, 'associated_ip'] = ip_list

    # Source Manufacturer column
    mac_vendors = {}
    with open(MAC_VENDORS_JSON_FILE) as f:
        mac_vendors = json.load(f)
    mac_df["vendor"] = mac_df["mac"].apply(
        lambda mac: get_mac_vendor(mac_vendors, mac)
    )

    return mac_df