import logging
import os

from flask import Flask, render_template, request, send_file
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

    # Set output directory
    output_dir = os.path.join(os.getcwd(), "_tmp")
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    # set excel file
    excel_file = request.files.get("spreadsheet")
    if excel_file and excel_file.filename:
        excel_file.save(os.path.join(output_dir, excel_file.filename))

    # Get pcap file and Zeek logs if available
    pcap_file = request.files.get("pcapfile")
    if pcap_file and pcap_file.filename:
        pcap_file.save(os.path.join(output_dir, pcap_file.filename))

    zeek_logs = request.files.get("zeeklogs")
    if zeek_logs and zeek_logs.filename:
        zeek_logs.save(os.path.join(output_dir, zeek_logs.filename))

    memfile = generate(
        customer_name, output_dir, pcap_file, zeek_logs.filename, excel_file
    )

    return send_file(memfile, download_name=filename, as_attachment=True)
