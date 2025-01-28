# PwnConnect

![GitHub last commit](https://img.shields.io/github/last-commit/pwncat-offsec/PwnConnect)
![GitHub branches](https://img.shields.io/github/branches/pwncat-offsec/PwnConnect)
![GitHub stars](https://img.shields.io/github/stars/pwncat-offsec/PwnConnect)
![GitHub issues](https://img.shields.io/github/issues/pwncat-offsec/PwnConnect)
![GitHub license](https://img.shields.io/github/license/pwncat-offsec/PwnConnect)

This project is a web-based phishing simulation portal using Flask and OpenConnect to simulate a VPN login page. It provides a login interface for users to authenticate with their username and password, and supports OTP (One-Time Password) for two-factor authentication.

## Project Structure

- `app.py`: Main Flask application file.
- `LICENSE`: License file (Apache License 2.0).
- `README.md`: This file.
- `static/style.css`: CSS file for styling the web pages.
- `templates/login.html`: HTML template for the login page.
- `templates/otp.html`: HTML template for the OTP page.
- `utils/`: Directory for utility scripts.
  
## Prerequisites

- Python 3.x
- Flask
- pexpect
- OpenConnect

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/phishing-simulation-page.git
    cd phishing-simulation-page
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

3. Set the required environment variables:
    ```sh
    export VPN_SERVER="your_vpn_server"
    export SECRET_KEY="your_secret_key"
    export SESSIONS_KEY="your_sessions_key"
    export REDIRECT_URL="https://your_redirect_url"
    ```

## Usage

1. Run the Flask application:
    ```sh
    python app.py
    ```

2. Open your web browser and navigate to `http://localhost:5000`.

3. Enter your VPN username and password to log in.

4. If OTP is required, you will be redirected to the OTP page to enter your OTP.

## Future Improvements

- **Support for Other VPNs**: Extend support to other VPNs that OpenConnect supports, such as AnyConnect, Juniper, and Pulse Secure.
- **Improved Setup and Deployment**: Simplify the setup and deployment process, possibly by using Docker or other containerization technologies.
- **Multiple Tunnel Management**: Enhance the management of multiple VPN tunnels, allowing users to switch between different VPN connections seamlessly.
- **User Management**: Implement user management features, such as user roles and permissions.
- **Logging and Monitoring**: Add logging and monitoring capabilities to track user activity and system performance.
- **Security Enhancements**: Improve security measures, such as encryption of sensitive data and protection against common web vulnerabilities.
- **Responsive Design**: Ensure the web interface is responsive and works well on various devices, including mobile phones and tablets.
- **Localization**: Add support for multiple languages to make the portal accessible to a wider audience.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](http://_vscodecontentref_/1) file for details.

## Authors

This project was created by PWNCAT company and coded by [@k0x-offsec](https://github.com/k0x-offsec) and [@r4m-offsec](https://github.com/r4m-offsec).