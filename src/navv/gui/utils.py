import os
import logging

logger = logging.getLogger(__name__)


def get_pcap_file() -> tuple[str, str, str]:
    """Get the pcap file from the current working directory."""
    pcap_files = set()
    for file in os.listdir(os.getcwd()):
        if file.endswith(".pcap"):
            logger.info(f"Found pcap file: {file} in {os.getcwd()}")
            pcap_files.add(file)

    # No PCAP file found
    if len(pcap_files) == 0:
        logger.error(f"Could not find a pcap file in {os.getcwd()}")
        return (
            "",
            "Could not find a pcap file in the current directory. Please upload.",
            "warning",
        )

    # Multiple PCAP files found
    if len(pcap_files) > 1:
        logger.error(f"Found multiple pcap files, please remove all but one.")
        return "", "Found multiple pcap files. Please remove all but one.", "danger"

    filename = pcap_files.pop()
    return filename, f"{filename} detected and uploaded successfully.", "success"
