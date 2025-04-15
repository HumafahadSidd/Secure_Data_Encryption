# Secure Data Storage System

A Streamlit-based secure data storage and retrieval system that allows users to store and retrieve encrypted data using passkeys.

## Features

- Multi-user support with secure authentication
- Persistent data storage using JSON files
- Secure data encryption using Fernet
- PBKDF2 password hashing
- Time-based account lockout
- JWT-based session management
- User-friendly interface

## Security Features

- Data is encrypted using Fernet (symmetric encryption)
- Passwords are hashed using PBKDF2
- Account lockout after multiple failed attempts
- JWT tokens for session management
- Persistent storage with encrypted data
- Separate encryption key storage

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the Streamlit app:
```bash
streamlit run app.py
```

2. The application will open in your default web browser
3. You can:
   - Register a new account
   - Login with your credentials
   - Store new data with a passkey
   - Retrieve your stored data using the data ID and passkey
   - Logout when done

## Data Storage

The system uses two JSON files for storage:
- `users.json`: Stores user accounts and hashed passwords
- `encrypted_data.json`: Stores encrypted data for all users

The encryption key is stored separately in `encryption.key`.

## Security Notes

- The system implements a 15-minute lockout after 3 failed login attempts
- Passwords must be at least 8 characters long
- Each user's data is isolated and can only be accessed by the owner
- JWT tokens expire after 30 minutes
- All sensitive data is encrypted before storage

## Note

This is a demonstration application. While it implements several security best practices, it should not be used for storing highly sensitive data without additional security measures. 