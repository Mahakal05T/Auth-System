from http.server import SimpleHTTPRequestHandler, HTTPServer
import json
import bcrypt  # 🔒 Secure Password Hashing
import random
import mysql.connector as mysql
import os
import re
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
from datetime import datetime, timedelta
from dotenv import load_dotenv
from ratelimit import limits, sleep_and_retry  # 🚫 Rate Limiting

# Load .env File for Security
dotenv_path = os.path.join(os.path.dirname(__file__), "credentials.env")
load_dotenv(dotenv_path)

# 🔗 Secure Database Connection
def connect_db():
    return mysql.connect(
        host="localhost",
        user="root",
        password="",
        database="auth_system",
    )

# 🔒 Secure Password Hashing with Bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# 🔑 Verify Passwords
def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

# Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Validate Email Format
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# ✅ Ensure Strong Passwords
def is_strong_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(not char.isalnum() for char in password)

# 📩 Send OTP via Email
def send_otp_email(email, otp):
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")

    if not email_user or not email_pass:
        print("❌ Email credentials missing")
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
        return True
    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        return False

# 📲 Send OTP via SMS (Twilio)
def send_otp_sms(phone, otp):
    twilio_sid = os.getenv("TWILIO_SID")
    twilio_token = os.getenv("TWILIO_TOKEN")
    twilio_phone = os.getenv("TWILIO_PHONE")

    if not twilio_sid or not twilio_token or not twilio_phone:
        return False

    try:
        client = Client(twilio_sid, twilio_token)
        client.messages.create(body=f"Your OTP code is: {otp}", from_=twilio_phone, to=phone)
        return True
    except:
        return False

class AuthHandler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Set-Cookie", "Secure; HttpOnly; SameSite=Strict")  # 🔒 Secure Cookies
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            self.path = "/templates/login.html"
        elif self.path.startswith("/static/"):
            self.path = self.path[1:]
        elif self.path.startswith("/templates/"):
            self.path = self.path[1:]
        return super().do_GET()

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        if self.path == "/register":
            self.register_user(data)
        elif self.path == "/login":
            self.login_user(data)
        elif self.path == "/forgot-password":
            self.forgot_password(data)
        elif self.path == "/validate-otp":
            self.validate_otp(data)
        elif self.path == "/reset-password":
            self.reset_password(data)

    def register_user(self, data):
        username, email, phone, password = data["username"], data["email"], data["phone"], data["password"]

        if not is_strong_password(password):
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Weak password"}).encode())
            return

        hashed_password = hash_password(password)
        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE email=%s OR phone=%s OR username=%s", (email, phone, username))
            if cursor.fetchone():
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "User already exists"}).encode())
                return

            cursor.execute("INSERT INTO users (username, email, phone, password_hash) VALUES (%s, %s, %s, %s)", 
                           (username, email, phone, hashed_password))
            conn.commit()
            self._set_headers(200)
            self.wfile.write(json.dumps({"message": "User registered successfully"}).encode())
        finally:
            conn.close()

    def login_user(self, data):
        identifier, password = data["identifier"], data["password"]
        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE email=%s OR phone=%s OR username=%s", 
                           (identifier, identifier, identifier))
            user = cursor.fetchone()
            if user and check_password(user["password_hash"], password):
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Login successful"}).encode())
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Invalid credentials"}).encode())
        finally:
            conn.close()

    @sleep_and_retry
    @limits(calls=3, period=60)  # 🚫 Limit OTP requests (3 per minute)
    def forgot_password(self, data):
        identifier = data["identifier"]
        otp = generate_otp()
        expiry_time = datetime.now() + timedelta(minutes=10)

        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT email, phone FROM users WHERE email=%s OR phone=%s", (identifier, identifier))
            user = cursor.fetchone()

            if not user:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "User not found"}).encode())
                return

            cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
            cursor.execute("INSERT INTO otp_codes (identifier, otp, expiry_time) VALUES (%s, %s, %s)", 
                           (identifier, otp, expiry_time))
            conn.commit()

            sent = send_otp_email(identifier, otp) if is_valid_email(identifier) else send_otp_sms(identifier, otp)

            if sent:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "OTP sent successfully"}).encode())
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": "Failed to send OTP"}).encode())

        finally:
            conn.close()
    
    def validate_otp(self, data):
        identifier, otp = data["identifier"], data["otp"]

        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM otp_codes WHERE identifier=%s AND otp=%s AND expiry_time > NOW()", 
                           (identifier, otp))
            otp_record = cursor.fetchone()

            if otp_record:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "OTP verified. Proceed to reset password."}).encode())
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Invalid or expired OTP"}).encode())
        finally:
            conn.close()

    def reset_password(self, data):
        identifier, new_password = data["identifier"], data["new_password"]

        if not is_strong_password(new_password):
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Weak password"}).encode())
            return

        hashed_password = hash_password(new_password)

        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("UPDATE users SET password_hash=%s WHERE email=%s OR phone=%s", (hashed_password, identifier, identifier))
            cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
            conn.commit()

            self._set_headers(200)
            self.wfile.write(json.dumps({"message": "Password reset successful"}).encode())
        finally:
            conn.close()

server = HTTPServer(("localhost", 8080), AuthHandler)
print("Server running on http://localhost:8080")
server.serve_forever()
