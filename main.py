import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
import time

# Generate a key (this should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# File to store encrypted data
DATA_FILE = "stored_data.json"

# Global variables
failed_attempts = 0
lockout_time = 0  # Timestamp for lockout

# Function to load data from a JSON file
def load_data():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Function to save data to a JSON file
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Function to hash the passkey (PBKDF2)
def hash_passkey(passkey):
    salt = os.urandom(16)  # Salt to ensure uniqueness
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    stored_data = load_data()

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# Function to check if login attempts are allowed
def can_attempt_login():
    global failed_attempts, lockout_time
    if failed_attempts >= 3:
        current_time = time.time()
        if current_time - lockout_time < 60:  # Lockout for 60 seconds
            return False
        else:
            failed_attempts = 0  # Reset failed attempts after lockout period
            return True
    return True

# Function to authenticate users
users = {
    "user1": {"password": "password123", "failed_attempts": 0, "data": {}},
    "user2": {"password": "password456", "failed_attempts": 0, "data": {}}
}

def user_login(username, password):
    if username in users and users[username]["password"] == password:
        users[username]["failed_attempts"] = 0
        return True
    else:
        if username in users:
            users[username]["failed_attempts"] += 1
        return False

def store_user_data(username, encrypted_text, passkey):
    if username not in users:
        users[username] = {"password": "", "failed_attempts": 0, "data": {}}
    users[username]["data"][encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hash_passkey(passkey)}
    save_data(users)

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Login":
    st.subheader("🔑 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if user_login(username, password):
            st.success("✅ Login successful")
            st.session_state.username = username
        else:
            st.error("❌ Invalid credentials")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    if "username" in st.session_state:
        username = st.session_state.username
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                encrypted_text = encrypt_data(user_data, passkey)
                store_user_data(username, encrypted_text, passkey)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.warning("Please log in to store data.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    if "username" in st.session_state:
        username = st.session_state.username
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.warning("Please log in to retrieve data.")
