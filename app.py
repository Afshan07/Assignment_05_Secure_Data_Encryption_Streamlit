import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Key generation
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}
failed_attempts = 0

# Hash function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for data in stored_data.values():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# UI
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.write("Welcome! Use this app to securely store and retrieve data.")

elif choice == "Store Data":
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("Data stored successfully!")

elif choice == "Retrieve Data":
    encrypted = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    if st.button("Decrypt"):
        if encrypted and passkey:
            result = decrypt_data(encrypted, passkey)
            if result:
                st.success(f"Decrypted Data: {result}")
            else:
                st.error(f"Wrong passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("Too many failed attempts. Redirecting to login...")
                    st.experimental_rerun()

elif choice == "Login":
    login = st.text_input("Master Password:", type="password")
    if st.button("Login"):
        if login == "admin123":
            failed_attempts = 0
            st.success("Reauthorized successfully!")
            st.experimental_rerun()
        else:
            st.error("Incorrect master password!")
