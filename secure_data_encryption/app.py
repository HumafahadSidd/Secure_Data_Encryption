import streamlit as st
from cryptography.fernet import Fernet
import hashlib
from typing import Dict, Optional
from auth import AuthManager
from data_manager import DataManager

# Initialize managers
auth_manager = AuthManager()
data_manager = DataManager()

# Initialize session state variables
if 'username' not in st.session_state:
    st.session_state.username = None
if 'access_token' not in st.session_state:
    st.session_state.access_token = None

def hash_passkey(passkey: str) -> str:
    """Hash the passkey using PBKDF2."""
    return auth_manager._hash_password(passkey)

def encrypt_data(data: str, passkey: str) -> Dict:
    """Encrypt data and store with hashed passkey."""
    encrypted_data = data_manager.cipher.encrypt(data.encode())
    return {
        "encrypted_text": encrypted_data.decode(),
        "passkey": hash_passkey(passkey)
    }

def decrypt_data(encrypted_data: Dict, passkey: str) -> Optional[str]:
    """Decrypt data if passkey matches."""
    if hash_passkey(passkey) == encrypted_data["passkey"]:
        return data_manager.cipher.decrypt(encrypted_data["encrypted_text"].encode()).decode()
    return None

def login_page():
    """Display login page."""
    st.title("Login")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            success, message = auth_manager.authenticate_user(username, password)
            if success:
                st.session_state.username = username
                st.session_state.access_token = auth_manager.create_access_token(username)
                st.rerun()
            else:
                st.error(message)
    
    with tab2:
        new_username = st.text_input("Username", key="register_username")
        new_password = st.text_input("Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        if st.button("Register"):
            if new_password != confirm_password:
                st.error("Passwords do not match")
            elif len(new_password) < 8:
                st.error("Password must be at least 8 characters long")
            else:
                if auth_manager.register_user(new_username, new_password):
                    st.success("Registration successful! Please login.")
                else:
                    st.error("Username already exists")

def store_data_page():
    """Page for storing new encrypted data."""
    st.title("Store New Data")
    
    data = st.text_area("Enter data to encrypt")
    passkey = st.text_input("Enter passkey", type="password")
    
    if st.button("Store Data"):
        if data and passkey:
            # Generate a unique key for storage
            data_id = f"data_{len(data_manager.get_user_data_ids(st.session_state.username)) + 1}"
            encrypted_data = encrypt_data(data, passkey)
            data_manager.store_data(st.session_state.username, data_id, encrypted_data)
            st.success("Data stored successfully!")
            st.info(f"Your data ID is: {data_id}")
        else:
            st.error("Please enter both data and passkey")

def retrieve_data_page():
    """Page for retrieving encrypted data."""
    st.title("Retrieve Data")
    
    # Get user's data IDs
    data_ids = data_manager.get_user_data_ids(st.session_state.username)
    if not data_ids:
        st.info("You have no stored data.")
        return
    
    data_id = st.selectbox("Select data ID", data_ids)
    passkey = st.text_input("Enter passkey", type="password")
    
    if st.button("Retrieve Data"):
        if passkey:
            encrypted_data = data_manager.get_data(st.session_state.username, data_id)
            if encrypted_data:
                decrypted_data = decrypt_data(encrypted_data, passkey)
                if decrypted_data:
                    st.success("Data retrieved successfully!")
                    st.text_area("Decrypted Data", decrypted_data, height=200)
                else:
                    st.error("Invalid passkey")
            else:
                st.error("Data not found")
        else:
            st.error("Please enter passkey")

def main():
    st.title("Secure Data Storage System")
    
    # Check authentication
    if st.session_state.access_token:
        username = auth_manager.verify_token(st.session_state.access_token)
        if not username:
            st.session_state.username = None
            st.session_state.access_token = None
            st.rerun()
    
    if not st.session_state.username:
        login_page()
        return
    
    # Display user info and logout button
    col1, col2 = st.columns([3, 1])
    with col1:
        st.write(f"Welcome, {st.session_state.username}!")
    with col2:
        if st.button("Logout"):
            st.session_state.username = None
            st.session_state.access_token = None
            st.rerun()
    
    # Navigation
    page = st.radio("Choose an option:", ["Store Data", "Retrieve Data"])
    
    if page == "Store Data":
        store_data_page()
    else:
        retrieve_data_page()

if __name__ == "__main__":
    main() 