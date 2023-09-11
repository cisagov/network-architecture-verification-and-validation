import logging
import os

from flask import Flask, render_template, send_from_directory


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)


@app.route("/")
def index():
    for file in os.listdir(os.getcwd()):
        if file.endswith(".pcap"):
            logger.info(f"Found pcap file: {file}")
            break
    return render_template("index.html")


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
