import logging
from flask import Flask, request, jsonify, send_from_directory, render_template
import json
import bcrypt
import random
import mysql.connector as mysql
import os
import re
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
from datetime import datetime, timedelta
from dotenv import load_dotenv
from ratelimit import limits, sleep_and_retry
import secrets

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
load_dotenv(os.path.join(os.path.dirname(__file__), "credentials.env"))

# ------------------ Utilities ------------------

def connect_db():
    try:
        conn = mysql.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            database=os.getenv("DB_NAME"),
        )
        logging.debug("Database connection established successfully.")
        return conn
    except Exception as e:
        logging.error(f"Error connecting to database: {e}")
        raise

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def generate_otp():
    return str(random.randint(100000, 999999))

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_strong_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(not char.isalnum() for char in password)

def send_otp_email(email, otp):
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")
    if not email_user or not email_pass:
        logging.error("Email credentials are not configured in .env")
        return False

    msg = MIMEText(f"Your OTP code is: {otp}")
    msg["Subject"] = "Password Reset OTP"
    msg["From"] = email_user
    msg["To"] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email_user, email_pass)
        server.sendmail(email_user, email, msg.as_string())
        server.quit()
        logging.debug(f"OTP email sent to {email}")
        return True
    except Exception as e:
        logging.error(f"Error sending OTP email to {email}: {e}")
        return False

def send_otp_sms(phone, otp):
    twilio_sid = os.getenv("TWILIO_SID")
    twilio_token = os.getenv("TWILIO_TOKEN")
    twilio_phone = os.getenv("TWILIO_PHONE")
    if not twilio_sid or not twilio_token or not twilio_phone:
        logging.error("Twilio credentials are not configured in .env")
        return False
    try:
        client = Client(twilio_sid, twilio_token)
        client.messages.create(body=f"Your OTP code is: {otp}", from_=twilio_phone, to=phone)
        logging.debug(f"OTP SMS sent to {phone}")
        return True
    except Exception as e:
        logging.error(f"Error sending OTP SMS to {phone}: {e}")
        return False

def send_reset_link_email(email, link):
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")
    if not email_user or not email_pass:
        logging.error("Email credentials are not configured in .env")
        return False

    msg = MIMEText(f"Click this link to reset your password: {link}")
    msg["Subject"] = "Reset Your Password"
    msg["From"] = email_user
    msg["To"] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email_user, email_pass)
        server.sendmail(email_user, email, msg.as_string())
        server.quit()
        logging.debug(f"Reset link email sent to {email}")
        return True
    except Exception as e:
        logging.error(f"Error sending reset link email to {email}: {e}")
        return False

def send_reset_link_sms(phone, link):
    twilio_sid = os.getenv("TWILIO_SID")
    twilio_token = os.getenv("TWILIO_TOKEN")
    twilio_phone = os.getenv("TWILIO_PHONE")
    if not twilio_sid or not twilio_token or not twilio_phone:
        logging.error("Twilio credentials are not configured in .env")
        return False
    try:
        client = Client(twilio_sid, twilio_token)
        client.messages.create(body=f"Reset your password: {link}", from_=twilio_phone, to=phone)
        logging.debug(f"Reset link SMS sent to {phone}")
        return True
    except Exception as e:
        logging.error(f"Error sending reset link SMS to {phone}: {e}")
        return False

# ------------------ UI Routes ------------------

@app.route("/")
def root():
    return render_template("login.html")

@app.route("/forgot_password", methods=["GET"])
def forgot_password_page():
    return render_template("forgot_password.html")

@app.route("/reset_password", methods=["GET"])
def reset_password_page():
    token = request.args.get("token")
    return render_template("reset_password.html", token=token)

@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    return render_template("dashboard.html")

@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

# ------------------ Register & Login ------------------

@app.route("/register", methods=["GET", "POST"])
def register_user():
    if request.method == "GET":
        return render_template("register.html")

    data = request.get_json()
    username, email, phone, password = data["username"], data["email"], data["phone"], data["password"]

    if not is_strong_password(password):
        logging.warning(f"Weak password attempt: {password}")
        return jsonify({"error": "Weak password"}), 400

    hashed_password = hash_password(password)
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email=%s OR phone=%s OR username=%s", (email, phone, username))
        if cursor.fetchone():
            logging.warning(f"User already exists with email/phone/username: {email}, {phone}, {username}")
            return jsonify({"error": "User already exists"}), 400

        cursor.execute("INSERT INTO users (username, email, phone, password_hash) VALUES (%s, %s, %s, %s)",
                       (username, email, phone, hashed_password))
        conn.commit()
        logging.info(f"User {username} registered successfully")
        return jsonify({"message": "User registered successfully"}), 200
    finally:
        conn.close()

@app.route("/login", methods=["GET", "POST"])
def login_user():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json()
    identifier, password = data["identifier"], data["password"]
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email=%s OR phone=%s OR username=%s",
                       (identifier, identifier, identifier))
        user = cursor.fetchone()
        if user and check_password(user["password_hash"], password):
            logging.info(f"User {identifier} logged in successfully.")
            return jsonify({"message": "Login successful"}), 200
        else:
            logging.warning(f"Invalid login attempt for {identifier}")
            return jsonify({"error": "Invalid credentials"}), 400
    finally:
        conn.close()

# ------------------ Combined OTP Send + Validation ------------------

@sleep_and_retry
@limits(calls=3, period=60)
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    identifier = data.get("identifier")
    otp = data.get("otp")

    logging.debug(f"Received forgot_password request: identifier={identifier}, otp={otp}")

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT email, phone FROM users WHERE email=%s OR phone=%s", (identifier, identifier))
        user = cursor.fetchone()

        if not user:
            logging.warning(f"User not found with identifier {identifier}")
            return jsonify({"error": "User not found"}), 400

        # OTP Validation
        if otp:
            cursor.execute("SELECT * FROM otp_codes WHERE identifier=%s AND expiry_time > NOW()", (identifier,))
            otp_record = cursor.fetchone()
            if otp_record and bcrypt.checkpw(otp.encode(), otp_record["otp"].encode()):
                import secrets
                token = secrets.token_urlsafe(32)
                expiry_time = datetime.now() + timedelta(minutes=30)

                cursor.execute("DELETE FROM reset_links WHERE identifier=%s", (identifier,))
                cursor.execute("INSERT INTO reset_links (identifier, token, expiry_time) VALUES (%s, %s, %s)",
                               (identifier, token, expiry_time))
                conn.commit()

                reset_url = f"http://127.0.0.1:5000/reset_password?token={token}"
                if is_valid_email(identifier):
                    send_reset_link_email(identifier, reset_url)
                else:
                    send_reset_link_sms(identifier, reset_url)

                logging.info(f"OTP verified and reset link sent for {identifier}")
                return jsonify({"message": "OTP verified. Reset link sent."}), 200
            else:
                logging.warning(f"Invalid or expired OTP for {identifier}")
                return jsonify({"error": "Invalid or expired OTP"}), 400

        # OTP Sending
        generated_otp = generate_otp()
        expiry_time = datetime.now() + timedelta(minutes=10)
        hashed_otp = bcrypt.hashpw(generated_otp.encode(), bcrypt.gensalt()).decode()

        cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
        cursor.execute("INSERT INTO otp_codes (identifier, otp, expiry_time) VALUES (%s, %s, %s)",
                       (identifier, hashed_otp, expiry_time))
        conn.commit()

        sent = send_otp_email(identifier, generated_otp) if is_valid_email(identifier) else send_otp_sms(identifier, generated_otp)
        if sent:
            logging.info(f"OTP sent successfully to {identifier}")
            return jsonify({"message": "OTP sent successfully"}), 200
        else:
            logging.error(f"Failed to send OTP to {identifier}")
            return jsonify({"error": "Failed to send OTP"}), 500

    except Exception as e:
        logging.error(f"Error in forgot_password route: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        conn.close()

# ------------------ Reset Password ------------------

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')

        logging.debug(f"Received reset password request: token={token}, new_password={new_password}")

        if not token or not new_password:
            logging.warning("Missing token or new_password")
            return jsonify({'error': 'Missing token or new_password'}), 400

        conn = connect_db()
        cursor = conn.cursor()

        # Get the identifier associated with the token
        cursor.execute("SELECT identifier FROM reset_links WHERE token = %s", (token,))
        result = cursor.fetchone()

        if not result:
            return jsonify({'error': 'Invalid or expired token'}), 400

        identifier = result[0]

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

        # Update the user's password
        cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s OR phone = %s", (hashed_password, identifier, identifier))

        # Delete the token
        cursor.execute("DELETE FROM reset_links WHERE token = %s", (token,))
        conn.commit()

        return jsonify({'message': 'Password updated successfully'})

    except Exception as e:
        logging.error(f"Error in reset_password route: {e}")
        return jsonify({'error': 'Server error'}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()


if __name__ == "__main__":
    app.run(debug=True)
