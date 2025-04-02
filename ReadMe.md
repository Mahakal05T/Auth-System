# Authentication System Server

This is a simple authentication system using Python's built-in `http.server` module. It provides user registration, login, password reset, and OTP-based authentication using MySQL as the database.

## Features
- ✅ User Registration with Password Hashing (bcrypt)
- 🔐 Secure User Login with Password Verification
- 🔑 Forgot Password with OTP Verification (Email/SMS)
- 🔒 Secure Password Storage & Validation
- 📩 Email and SMS OTP Sending
- 🚫 Rate Limiting for OTP Requests
- 📁 Simple HTTP Server for Authentication

## Technologies Used
- Python (`http.server`, `json`, `bcrypt`, `mysql.connector`, `smtplib`, `twilio`)
- MySQL for Database Management
- Email Sending using SMTP (Gmail)
- SMS Sending using Twilio

## Prerequisites
Ensure you have the following installed:
- Python 3.x
- MySQL Server
- Required Python packages (install using `pip`):
  ```bash
  pip install bcrypt mysql-connector-python twilio python-dotenv ratelimit
  ```
- `.env` file containing:
  ```ini
  EMAIL_USER=your-email@gmail.com
  EMAIL_PASS=your-email-password
  TWILIO_SID=your-twilio-sid
  TWILIO_TOKEN=your-twilio-auth-token
  TWILIO_PHONE=your-twilio-phone-number
  ```

## Database Setup
Run the following SQL queries to set up the database:
```sql
CREATE DATABASE auth_system;
USE auth_system;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE otp_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(100) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    expiry_time DATETIME NOT NULL
);
```

## Running the Server
Start the authentication server by running:
```bash
python server.py
```
It will start the server on `http://localhost:8080`.

## API Endpoints
### 1. Register a New User
**POST** `/register`
#### Request Body (JSON)
```json
{
    "username": "user123",
    "email": "user@example.com",
    "phone": "+1234567890",
    "password": "Secure@123"
}
```
#### Response
```json
{"message": "User registered successfully"}
```

### 2. User Login
**POST** `/login`
#### Request Body (JSON)
```json
{
    "identifier": "user@example.com",
    "password": "Secure@123"
}
```
#### Response
```json
{"message": "Login successful"}
```

### 3. Forgot Password (Request OTP)
**POST** `/forgot-password`
#### Request Body (JSON)
```json
{
    "identifier": "user@example.com"
}
```
#### Response
```json
{"message": "OTP sent successfully"}
```

### 4. Validate OTP
**POST** `/validate-otp`
#### Request Body (JSON)
```json
{
    "identifier": "user@example.com",
    "otp": "123456"
}
```
#### Response
```json
{"message": "OTP verified. Proceed to reset password."}
```

### 5. Reset Password
**POST** `/reset-password`
#### Request Body (JSON)
```json
{
    "identifier": "user@example.com",
    "new_password": "NewSecure@456"
}
```
#### Response
```json
{"message": "Password reset successful"}
```

## Security Features
- 🛡️ Passwords are hashed using Bcrypt
- 🔒 Secure Cookies (`Secure; HttpOnly; SameSite=Strict`)
- 🚫 Rate limiting for OTP requests (3 requests per minute)

## Notes
- The system supports login using email, phone, or username.
- OTPs expire in 10 minutes.
- Ensure MySQL is running before starting the server.

## License
MIT License

