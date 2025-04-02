CREATE DATABASE auth_system;
USE auth_system;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(15) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE otp_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(100) NOT NULL,  -- Email or Phone
    otp VARCHAR(6) NOT NULL,
    expiry_time TIMESTAMP NOT NULL,
    UNIQUE(identifier)  -- Ensure only one OTP per user
);
