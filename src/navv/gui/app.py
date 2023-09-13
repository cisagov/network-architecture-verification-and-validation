import logging
import os

from flask import Flask, render_template, request, send_from_directory
from navv.gui.bll import generate

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


@app.route("/download", methods=["POST"])
def download():
    """Download the network analysis excel file."""
    # Get customer name
    customer_name = request.form["customername"]
    filename = f"{customer_name}_network_analysis.xlsx"

    # Get pcap file and Zeek logs if available
    pcap_file = request.files.get("pcapfile")
    if pcap_file.filename:
        pcap_file.save(pcap_file.filename)
    zeek_logs = request.files.get("zeeklogs")
    if zeek_logs:
        zeek_logs.save(zeek_logs.filename)

    generate(customer_name, os.getcwd(), pcap_file, zeek_logs)
