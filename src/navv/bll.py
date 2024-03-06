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
def get_inventory_report_df(zeek_df: pd.DataFrame):
    """Return a pandas dataframe of the inventory report data."""
    zeek_df["port_and_proto"] = zeek_df["port"] + "/" + zeek_df["proto"]

    zeek_df["src_ipv4"] = zeek_df["src_ip"].apply(
        lambda ip: ip if is_ipv4_address(ip) else None
    )
    zeek_df["src_ipv6"] = zeek_df["src_ip"].apply(
        lambda ip: ip if is_ipv6_address(ip) else None
    )

    zeek_df["dst_ipv4"] = zeek_df["dst_ip"].apply(
        lambda ip: ip if is_ipv4_address(ip) else None
    )
    zeek_df["dst_ipv6"] = zeek_df["dst_ip"].apply(
        lambda ip: ip if is_ipv6_address(ip) else None
    )

    src_df = zeek_df[
        [
            "src_mac",
            "src_ipv4",
            "src_hostname",
            "src_ipv6",
            "dst_ipv4",
            "dst_hostname",
            "dst_ipv6",
            "port_and_proto",
        ]
    ].reset_index(drop=True)
    src_df["mac"] = src_df["src_mac"]

    dst_df = zeek_df[
        [
            "dst_mac",
            "src_ipv4",
            "src_hostname",
            "src_ipv6",
            "dst_ipv4",
            "dst_hostname",
            "dst_ipv6",
            "port_and_proto",
        ]
    ].reset_index(drop=True)
    dst_df["mac"] = dst_df["dst_mac"]

    df = (
        pd.concat([src_df, dst_df])
        .reset_index(drop=True)
        .drop(columns=["src_mac", "dst_mac"])
        .drop_duplicates(
            subset=[
                "src_ipv4",
                "src_hostname",
                "src_ipv6",
                "dst_ipv4",
                "dst_hostname",
                "dst_ipv6",
                "port_and_proto",
            ]
        )
    )

    grouped_df = (
        df.groupby("mac", as_index=False)
        .agg(
            {
                "src_ipv4": list,
                "src_hostname": list,
                "src_ipv6": list,
                "dst_ipv4": list,
                "dst_hostname": list,
                "dst_ipv6": list,
                "port_and_proto": list,
            }
        )
        .reset_index()
    )

    mac_vendors = {}
    with open(MAC_VENDORS_JSON_FILE) as f:
        mac_vendors = json.load(f)
    grouped_df["vendor"] = grouped_df["mac"].apply(
        lambda mac: get_mac_vendor(mac_vendors, mac)
    )
    grouped_df["ipv4"] = (grouped_df["src_ipv4"] + grouped_df["dst_ipv4"]).apply(
        lambda ip: list(set(ip))
    )
    grouped_df["ipv6"] = (grouped_df["src_ipv6"] + grouped_df["dst_ipv6"]).apply(
        lambda ip: list(set(ip))
    )
    grouped_df["hostname"] = (
        grouped_df["src_hostname"] + grouped_df["dst_hostname"]
    ).apply(lambda hostname: list(set(hostname)))

    grouped_df.drop(
        columns=[
            "src_ipv4",
            "src_hostname",
            "src_ipv6",
            "dst_ipv4",
            "dst_hostname",
            "dst_ipv6",
        ],
        inplace=True,
    )

    return grouped_df


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