from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import bcrypt
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.secret_key = "supersecretkey"


def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # convert keys to storable format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem, private_pem

# AES used for actual message encryption
def encrypt_message(message, receiver_public_key_pem):
    receiver_public_key = serialization.load_pem_public_key(receiver_public_key_pem)

    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext_with_tag = aesgcm.encrypt(nonce, message.encode(), None)
    # RSA encrypts the AES key
    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return encrypted_key, nonce, tag, ciphertext


def decrypt_message(encrypted_key, nonce, tag, ciphertext, receiver_private_key_pem):
    receiver_private_key = serialization.load_pem_private_key(
        receiver_private_key_pem,
        password=None
    )

    aes_key = receiver_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)

    return plaintext.decode()


@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        public_key, private_key = generate_rsa_keys()

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, public_key, private_key) VALUES (?, ?, ?, ?)",
                (username, password_hash, public_key, private_key)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            error = "User already exists."
            return render_template("register.html", error=error)

        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            session["username"] = username
            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    message_status = None
    error = None

    if request.method == "POST":
        sender = session["username"]
        receiver = request.form["receiver"].strip()
        message = request.form["message"].strip()

        conn = get_db_connection()
        receiver_user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (receiver,)
        ).fetchone()

        if not receiver_user:
            conn.close()
            error = "Receiver not found."
        else:
            encrypted_key, nonce, tag, ciphertext = encrypt_message(
                message,
                receiver_user["public_key"]
            )

            conn.execute(
                """
                INSERT INTO messages (sender, receiver, encrypted_key, nonce, tag, ciphertext)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sender, receiver, encrypted_key, nonce, tag, ciphertext)
            )
            conn.commit()
            conn.close()
            message_status = "Encrypted message sent!"

    return render_template(
        "dashboard.html",
        username=session["username"],
        message_status=message_status,
        error=error
    )


@app.route("/inbox")
def inbox():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (session["username"],)
    ).fetchone()

    messages = conn.execute(
        "SELECT * FROM messages WHERE receiver = ? ORDER BY id DESC",
        (session["username"],)
    ).fetchall()
    conn.close()

    decrypted_messages = []

    for msg in messages:
        try:
            decrypted = decrypt_message(
                msg["encrypted_key"],
                msg["nonce"],
                msg["tag"],
                msg["ciphertext"],
                user["private_key"]
            )
        except Exception:
            decrypted = "[Could not decrypt message]"

        decrypted_messages.append({
            "sender": msg["sender"],
            "message": decrypted,
            "timestamp": msg["timestamp"]
        })

    return render_template(
        "inbox.html",
        username=session["username"],
        messages=decrypted_messages
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)