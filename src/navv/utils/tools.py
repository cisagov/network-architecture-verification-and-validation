import json
import logging
from os import path

logger = logging.getLogger(__name__)

MAC_VENDORS_JSON_FILE = path.abspath(
    __file__ + "/../../" + "data/mac-vendors-export.json"
)


def get_mac_vendor(mac_address: str) -> str:
    """Return the vendor of the MAC address."""
    mac_address = mac_address.upper()

    with open(MAC_VENDORS_JSON_FILE) as f:
        mac_vendors = json.load(f)

    return [
        vendor["vendorName"]
        for vendor in mac_vendors
        if mac_address.startswith(vendor["macPrefix"])
    ][0]
