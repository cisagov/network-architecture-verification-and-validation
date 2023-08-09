from flask import Flask

from navv.message_handler import warning_msg


app = Flask(__name__)


@app.route("/")
def index():
    return "<h1>NAVV GUI</h1>"
