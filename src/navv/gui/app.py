import logging
import os

from flask import Flask, render_template, send_from_directory

from navv.gui.utils import get_pcap_file


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)


@app.route("/")
def index():
    """Home page."""
    pcap_file, pcap_msg, pcap_msg_color = get_pcap_file()

    return render_template(
        "home.html",
        pcap_file=pcap_file,
        pcap_msg=pcap_msg,
        pcap_msg_color=pcap_msg_color,
    )


@app.route("/new-analysis")
def new_analysis():
    pcap_file, pcap_msg, pcap_msg_color = get_pcap_file()

    return render_template(
        "create_new.html",
        pcap_file=pcap_file,
        pcap_msg=pcap_msg,
        pcap_msg_color=pcap_msg_color,
    )


@app.route("/existing-analysis")
def existing_analysis():
    pcap_file, pcap_msg, pcap_msg_color = get_pcap_file()

    return render_template(
        "update_existing.html",
        pcap_file=pcap_file,
        pcap_msg=pcap_msg,
        pcap_msg_color=pcap_msg_color,
    )


@app.route("/download")
def download():
    """Download the network analysis excel file."""
    filename = "test-customer_network_analysis.xlsx"
    current_path = os.getcwd()

    if not os.path.isfile(os.path.join(current_path, filename)):
        logger.error(f"File {filename} not found in {current_path}")

    return send_from_directory(
        current_path,
        filename,
        as_attachment=True,
    )
