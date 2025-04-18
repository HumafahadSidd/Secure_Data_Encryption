import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime, timedelta
import time

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_failed_attempt' not in st.session_state:
    st.session_state.last_failed_attempt = None
if 'is_locked' not in st.session_state:
    st.session_state.is_locked = False
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = None

# Generate a key (this should be stored securely in production)
if 'cipher' not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)

# Function to hash passkey using PBKDF2
def hash_passkey(passkey):
    salt = b'secure_salt'  # In production, use a unique salt per user
    return hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        salt,
        100000  # Number of iterations
    ).hex()

# Function to encrypt data
def encrypt_data(text, passkey):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    # Check if system is locked
    if st.session_state.is_locked:
        if datetime.now() < st.session_state.lockout_until:
            remaining_time = (st.session_state.lockout_until - datetime.now()).seconds
            st.error(f"System is locked. Try again in {remaining_time} seconds.")
            return None
        else:
            st.session_state.is_locked = False
            st.session_state.failed_attempts = 0
    
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    st.session_state.last_failed_attempt = datetime.now()
    
    # Implement lockout after 3 failed attempts
    if st.session_state.failed_attempts >= 3:
        st.session_state.is_locked = True
        st.session_state.lockout_until = datetime.now() + timedelta(minutes=5)
        st.error("Too many failed attempts! System locked for 5 minutes.")
    
    return None

# Function to save data to JSON file
def save_data():
    with open('secure_data.json', 'w') as f:
        json.dump(st.session_state.stored_data, f)

# Function to load data from JSON file
def load_data():
    if os.path.exists('secure_data.json'):
        with open('secure_data.json', 'r') as f:
            st.session_state.stored_data = json.load(f)

# Load data on startup
load_data()

# Streamlit UI
st.set_page_config(
    page_title="Secure Data System",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("""
    This application allows you to securely store and retrieve data using unique passkeys.
    
    Features:
    - 🔐 Secure encryption using Fernet
    - 🔑 PBKDF2 key hashing
    - ⚡ In-memory and file-based storage
    - 🔒 Automatic lockout after 3 failed attempts
    - ⏱️ 5-minute lockout period
    """)
    
    # Display system status
    st.sidebar.markdown("---")
    st.sidebar.subheader("System Status")
    if st.session_state.is_locked:
        remaining_time = (st.session_state.lockout_until - datetime.now()).seconds
        st.sidebar.warning(f"🔒 System Locked ({(remaining_time // 60)}m {(remaining_time % 60)}s remaining)")
    else:
        st.sidebar.success("✅ System Active")
    st.sidebar.info(f"Failed Attempts: {st.session_state.failed_attempts}/3")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    col1, col2 = st.columns(2)
    with col1:
        user_data = st.text_area("Enter Data to Encrypt:", height=200)
    with col2:
        passkey = st.text_input("Enter Passkey:", type="password")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    
    if st.button("🔒 Encrypt & Save", type="primary"):
        if not user_data or not passkey:
            st.error("⚠️ Both data and passkey are required!")
        elif passkey != confirm_passkey:
            st.error("⚠️ Passkeys do not match!")
        else:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "created_at": datetime.now().isoformat()
            }
            save_data()
            st.success("✅ Data stored securely!")
            
            # Show encrypted data
            st.info("🔐 Your encrypted data (save this to retrieve later):")
            st.code(encrypted_text)

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if st.session_state.is_locked:
        remaining_time = (st.session_state.lockout_until - datetime.now()).seconds
        st.error(f"System is locked. Try again in {remaining_time} seconds.")
    else:
        encrypted_text = st.text_area("Enter Encrypted Data:", height=100)
        passkey = st.text_input("Enter Passkey:", type="password")
        
        if st.button("🔓 Decrypt", type="primary"):
            if not encrypted_text or not passkey:
                st.error("⚠️ Both fields are required!")
            else:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                
                if decrypted_text:
                    st.success("✅ Data decrypted successfully!")
                    st.info("Decrypted Data:")
                    st.code(decrypted_text)
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if not st.session_state.is_locked:
        st.info("No reauthorization needed. The system is not locked.")
        st.stop()
    
    remaining_time = (st.session_state.lockout_until - datetime.now()).seconds
    if remaining_time > 0:
        st.warning(f"System is locked for {(remaining_time // 60)}m {(remaining_time % 60)}s more.")
        st.stop()
        st.stop()
    
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("🔑 Login", type="primary"):
        if login_pass == "admin123":  # In production, use proper authentication
            st.session_state.is_locked = False
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            time.sleep(1)
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!") 