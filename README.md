# Secure Messaging App

This is a secure messaging web app I built using Flask. It uses RSA and AES encryption to protect messages, along with bcrypt for user authentication.

## Features
- User registration and login
- Password hashing with bcrypt
- Each user gets their own RSA key pair
- Messages are encrypted using AES-GCM
- AES keys are encrypted using RSA
- Messages are stored securely in SQLite
- Inbox shows decrypted messages with timestamps

## Tech Stack
- Python (Flask)
- SQLite
- HTML/CSS
- bcrypt
- cryptography library

## How it works
When a user registers, they are assigned a public/private RSA key pair.

When sending a message:
- A random AES key is generated
- The message is encrypted using AES-GCM
- The AES key is encrypted using the receiver’s public RSA key
- Everything is stored in the database

When receiving a message:
- The AES key is decrypted using the receiver’s private key
- The message is decrypted and displayed in the inbox

## Running the app
```bash
source venv/bin/activate
python3 app.py
