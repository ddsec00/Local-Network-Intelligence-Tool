from flask import Flask, jsonify, render_template
import time

# Import your shared data from main.py
# (IMPORTANT: main.py must be running in same project)
from main import event_log, connection_tracker

app = Flask(__name__)

# =====================================================
# HOME PAGE (UI)
# =====================================================
@app.route("/")
def home():
    return render_template("index.html")


# =====================================================
# EVENTS API (for live updates)
# =====================================================
@app.route("/api/events")
def get_events():
    return jsonify(event_log[-100:])  # last 100 events only


# =====================================================
# CONNECTIONS API
# =====================================================
@app.route("/api/connections")
def get_connections():
    return jsonify(connection_tracker)


# =====================================================
# START SERVER
# =====================================================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)