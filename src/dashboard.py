from flask import Flask, request, jsonify

app = Flask(__name__)

# ----------------------------------------------------
# This is our temporary storage - think of it like a 
# whiteboard where the sniffer posts its findings.
#
# The sniffer (main.py) writes here, and the dashboard
# reads from here whenever it needs fresh data.
# ----------------------------------------------------
latest_data = {
    "events": [],           # List of recent network events
    "connections": {},      # Active connection details
    "stats": {}            # Various statistics and counters
}


# ----------------------------------------------------
# This is the "drop-off point" where the sniffer delivers
# its latest data.
#
# When main.py has new information, it sends a POST
# request to this URL:
# http://127.0.0.1:5000/update
# ----------------------------------------------------
@app.route("/update", methods=["POST"])
def update():

    global latest_data

    # Grab the JSON payload from the sniffer and
    # replace our stored data with the fresh stuff
    latest_data = request.get_json()

    print("Received update from sniffer.")

    # Let the sniffer know we got it
    return jsonify({"status": "received"})


# ----------------------------------------------------
# A quick way to peek at what's currently stored.
# Handy for testing or debugging.
#
# Just visit this in your browser:
# http://127.0.0.1:5000/data
# ----------------------------------------------------
@app.route("/data")
def data():

    return jsonify(latest_data)


# ----------------------------------------------------
# Fire up the Flask server and start listening
# ----------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)