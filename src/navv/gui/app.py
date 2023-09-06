from flask import Flask, render_template

from navv.message_handler import warning_msg


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")
