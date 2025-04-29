# Authentication System (Flask + MySQL)

This project is a secure user authentication system built with **Flask** and **MySQL**, supporting:
- User registration
- Login
- Forgot password with **OTP verification** (Email or SMS)
- Password reset via **secure token-based links**
- Admin dashboard access
- Rate limiting for OTPs
- Environment variable usage for credentials

---

## Features
- Secure password hashing using **bcrypt**
- OTP verification system via **Twilio SMS** or email
- Rate limiting for OTP requests
- Token-based password reset after OTP verification
- Admin user management
- Responsive frontend with HTML templates

---

## Tech Stack
- Python (Flask)
- MySQL
- HTML/CSS
- Twilio API
- dotenv for environment variables
- bcrypt for password hashing
- ratelimit for OTP protection

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Mahakal05T/Auth-System.git
cd Auth-System 
```

### 2. Create Virtual Environment (optional but recommended)
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install Requirements
First, create a file named `requirements.txt` with the following content:

```plaintext
Flask==3.0.2
mysql-connector-python==8.3.0
bcrypt==4.1.2
twilio==9.0.5
python-dotenv==1.0.1
ratelimit==2.2.1
```

Then install:
```bash
pip install -r requirements.txt
```

---

## 4. Configure Environment Variables
Create a `.env` file (or `credentials.env`) in the project directory:

```env
# Database
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_db_password
DB_NAME=your_database_name

# Twilio
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=your_twilio_phone_number

# Email Settings (if using email OTPs)
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_email_password
SECRET_KEY=your_flask_secret_key
```

> 🔥 Make sure to never push your `.env` file to public repositories!

---

## 5. Run the Flask Application
```bash
python app.py
```
Visit:
```
http://127.0.0.1:5000/
```

---

## Folder Structure
```bash
/your-repo
  |-- app.py
  |-- requirements.txt
  |-- /templates
      |-- login.html
      |-- register.html
      |-- forgot_password.html
      |-- reset_password.html
      |-- dashboard.html
  |-- /static
      |-- (CSS, JS, images)
  |-- credentials.env
  |-- README.md
```

---

## Notes
- Ensure that your MySQL database and tables are correctly set up before running the application.
- Adjust Twilio settings if you are sending SMS OTPs internationally.
- Flask’s `SECRET_KEY` should be strong and random for production environments.
- You can extend the dashboard to show more user data or analytics!

---

## License
This project is licensed under the MIT License.
