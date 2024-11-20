import sqlite3
import base64
import uuid
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, abort
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
from time import time

app = Flask(__name__)

DATABASE = 'totally_not_my_privateKeys.db'
SECRET_KEY = os.environ.get('NOT_MY_KEY')
assert SECRET_KEY, "Environment variable NOT_MY_KEY is required!"

ph = PasswordHasher()

# Rate-limiting parameters
RATE_LIMIT = 10  # Max number of requests per second
TIME_WINDOW = 1  # Time window in seconds (1 second)

# Store timestamps of successful authentication attempts per IP
auth_attempts = {}

# --- Rate-Limiting Logic ---
def is_rate_limited(ip):
    """Check if the IP is rate-limited based on the number of successful attempts."""
    current_time = time()
    timestamps = auth_attempts.get(ip, [])
    timestamps = [t for t in timestamps if current_time - t < TIME_WINDOW]
    
    if len(timestamps) >= RATE_LIMIT:
        return True
    else:
        timestamps.append(current_time)
        auth_attempts[ip] = timestamps
        return False

# --- AES Encryption of Private Keys ---
def getAesKey():
    """Derive a 256-bit AES key from the provided secret key."""
    salt = b'\x00' * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(SECRET_KEY.encode())

def encryptAes(data):
    """Encrypt data using AES."""
    key = getAesKey()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decryptAes(data):
    """Decrypt data using AES."""
    key = getAesKey()
    raw = base64.b64decode(data)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --- Database Setup ---
def createDb():
    """Create the SQLite database and the required tables."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()

def insertKeyIntoDb(key, expiry):
    """Insert an encrypted key into the database."""
    encryptedKey = encryptAes(key)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encryptedKey, expiry))
        conn.commit()

def getValidKeysFromDb(expired=False):
    """Retrieve encrypted keys from the database based on expiration status."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        now = int(datetime.utcnow().timestamp())
        query = 'SELECT kid, key FROM keys WHERE exp <= ?' if expired else 'SELECT kid, key FROM keys WHERE exp > ?'
        cursor.execute(query, (now,))
        keys = [(kid, decryptAes(key)) for kid, key in cursor.fetchall()]
    return keys

def generateRsaKeyPair():
    """Generate RSA key pair."""
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unencryptedPrivateKey = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return unencryptedPrivateKey

# --- User Registration ---
@app.route('/register', methods=['POST'])
def register():
    """Register a new user with secure password and store in DB."""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    if not username or not email:
        return jsonify({"message": "Username and email are required"}), 400

    password = str(uuid.uuid4())
    passwordHash = ph.hash(password)
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                (username, passwordHash, email)
            )
            conn.commit()
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username or email already exists"}), 409

# --- Authentication and Logging ---
@app.route('/auth', methods=['POST'])
def auth():
    """Authenticate the user and issue JWT."""
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    # Check if the IP is rate-limited
    ip = request.remote_addr
    print(f"Request from IP: {ip}")  # Debugging log
    if is_rate_limited(ip):
        return jsonify({"message": "Too many requests, please try again later."}), 429

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "Invalid credentials"}), 401

        userId, passwordHash = user
        try:
            ph.verify(passwordHash, password)
        except VerifyMismatchError:
            return jsonify({"message": "Invalid credentials"}), 401

        # Successful login, log the authentication
        keyData = getValidKeysFromDb(expired=False)
        if not keyData:
            return jsonify({"message": "No valid keys available"}), 404

        kid, privateKey = keyData[0]
        token = createJwtToken(privateKey, kid)

        cursor.execute(
            'INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)',
            (request.remote_addr, userId)
        )
        conn.commit()

    return jsonify({"token": token})

def createJwtToken(privateKey, kid):
    """Create JWT token using the private key."""
    key = jwk.JWK.from_pem(privateKey)
    claims = {"sub": "user", "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())}
    token = jwt.JWT(header={"alg": "RS256", "kid": str(kid)}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()

# --- Global Error Handler ---
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({"message": "Internal Server Error"}), 500

# --- Initialization ---
if __name__ == '__main__':
    createDb()
    # Generate and store RSA keys with expiry times
    key = generateRsaKeyPair()
    expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    insertKeyIntoDb(key, expiry)
    app.run(port=8080, debug=True)
