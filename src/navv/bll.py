import os
from ipaddress import IPv4Address, IPv6Address
import pandas as pd

from navv.zeek import perform_zeekcut
from navv.utilities import get_mac_vendor
from navv.validators import is_ipv4_address, is_ipv6_address


def get_zeek_data(zeek_logs):
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


def get_zeek_df(zeek_data: list):
    """Return a pandas dataframe of the conn.log data."""
    zeek_data = [row.split("\t") for row in zeek_data]

    return pd.DataFrame(
        zeek_data,
        columns=["src_ip", "dst_ip", "port", "proto", "conn", "src_mac", "dst_mac"],
    )


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
        ["src_mac", "src_ipv4", "src_ipv6", "dst_ipv4", "dst_ipv6", "port_and_proto"]
    ].reset_index(drop=True)
    src_df["mac"] = src_df["src_mac"]

    dst_df = zeek_df[
        ["dst_mac", "src_ipv4", "src_ipv6", "dst_ipv4", "dst_ipv6", "port_and_proto"]
    ].reset_index(drop=True)
    dst_df["mac"] = dst_df["dst_mac"]

    df = (
        pd.concat([src_df, dst_df])
        .reset_index(drop=True)
        .drop(columns=["src_mac", "dst_mac"])
        .drop_duplicates(
            subset=["src_ipv4", "src_ipv6", "dst_ipv4", "dst_ipv6", "port_and_proto"]
        )
    )
    df["vendor"] = df["mac"].apply(lambda mac: get_mac_vendor(mac))

    grouped_df = (
        df.groupby("mac", as_index=False)
        .agg(
            {
                "src_ipv4": list,
                "src_ipv6": list,
                "dst_ipv4": list,
                "dst_ipv6": list,
                "port_and_proto": list,
            }
        )
        .reset_index()
    )
    grouped_df["vendor"] = grouped_df["mac"].apply(lambda mac: get_mac_vendor(mac))
    grouped_df["ipv4"] = (grouped_df["src_ipv4"] + grouped_df["dst_ipv4"]).apply(
        lambda ip: list(set(ip))
    )
    grouped_df["ipv6"] = (grouped_df["src_ipv6"] + grouped_df["dst_ipv6"]).apply(
        lambda ip: list(set(ip))
    )
    grouped_df.drop(
        columns=["src_ipv4", "src_ipv6", "dst_ipv4", "dst_ipv6"], inplace=True
    )

    return grouped_df
