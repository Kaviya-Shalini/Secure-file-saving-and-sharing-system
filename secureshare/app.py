import streamlit as st
import os
import hashlib
from encryptor import encrypt_file, decrypt_file
from db import connect_db
from datetime import datetime

# --- Config ---
st.set_page_config(page_title="Secure Vault", page_icon="🔐", layout="wide")

# --- Session State ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "page" not in st.session_state:
    st.session_state.page = "Login"

# --- Upload Directory ---
upload_folder = "uploads"
os.makedirs(upload_folder, exist_ok=True)

# --- Sidebar Navigation ---
st.sidebar.title("🔐 Secure Vault")
menu_options = ["Register", "Login", "Upload Document", "My Wallet", "Shared With Me", "Delete Account", "Logout"]
menu = st.sidebar.radio("Navigation", menu_options)

st.session_state.page = menu


categories = ["Aadhaar", "PAN", "ID Proof", "Insurance", "School Marksheets", "College Certificates", "Asset Documents", "Other"]

# --- Register ---
if menu == "Register":
    st.subheader("🧾 Create Account")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    if st.button("Create"):
        conn = connect_db()
        if conn:
            try:
                cursor = conn.cursor()
                hashed = hashlib.sha256(pwd.encode()).hexdigest()
                cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (user, hashed))
                conn.commit()
                st.success("✅ User registered!")
            except Exception as e:
                st.error(f"❌ Error: {e}")
            finally:
                conn.close()

# --- Login ---
if menu == "Login":
    st.subheader("🔑 Login")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    if st.button("Login"):
        conn = connect_db()
        if conn:
            try:
                cursor = conn.cursor()
                hashed = hashlib.sha256(pwd.encode()).hexdigest()
                cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (user, hashed))
                if cursor.fetchone():
                    st.session_state.logged_in = True
                    st.session_state.username = user
                    st.success(f"🎉 Welcome, {user}!")
                else:
                    st.error("❌ Invalid credentials.")
            except Exception as e:
                st.error(f"⚠️ Login error: {e}")
            finally:
                conn.close()

# --- Logout ---
if menu == "Logout":
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.success("🚪 Logged out successfully.")

# --- Upload Document ---
if menu == "Upload Document":
    if st.session_state.logged_in:
        st.subheader("📤 Upload & Encrypt Document")
        file = st.file_uploader("Choose document")
        category = st.selectbox("📂 Select Category", categories)
        key = st.text_input("🔑 Enter 16-char AES Key")

        if file and key:
            if len(key) != 16:
                st.error("❌ AES key must be exactly 16 characters.")
            else:
                try:
                    data = file.read()
                    enc = encrypt_file(data, key)
                    enc_path = os.path.join(upload_folder, f"{file.name}.enc")
                    with open(enc_path, "wb") as f:
                        f.write(enc)

                    conn = connect_db()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            INSERT INTO files (filename, category, owner, aes_key)
                            VALUES (%s, %s, %s, %s)
                        """, (file.name, category, st.session_state.username, key))
                        conn.commit()
                        conn.close()
                        st.success("✅ File uploaded & encrypted!")
                except Exception as e:
                    st.error(f"🚫 Upload failed: {e}")
    else:
        st.warning("🔐 Login to upload.")

# --- My Wallet ---
if menu == "My Wallet":
    if st.session_state.logged_in:
        st.subheader(f"👛 {st.session_state.username}'s Wallet")
        conn = connect_db()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, filename, category, upload_time, aes_key FROM files WHERE owner=%s",
                           (st.session_state.username,))
            rows = cursor.fetchall()
            conn.close()

            if not rows:
                st.info("🗂️ No documents uploaded yet.")
            for row in rows:
                fid, filename, category, time, aes_key = row
                st.markdown(f"### 📄 {filename}")
                st.markdown(f"""**Category:** {category}  
**Uploaded:** {time}  
**Your AES Key:** `{aes_key}`  
""")

                col1, col2, col3 = st.columns([1, 1, 2])
                with col1:
                    if st.button(f"📥 Download {filename}", key=f"download_{fid}"):
                        try:
                            enc_path = os.path.join(upload_folder, f"{filename}.enc")
                            with open(enc_path, "rb") as f:
                                enc_data = f.read()
                            dec = decrypt_file(enc_data, aes_key)
                            st.download_button("📎 Download File", dec, file_name=filename, key=f"download_button_{fid}")
                        except Exception:
                            st.error("❌ Invalid key or file error.")
                with col2:
                    if st.button(f"🗑 Delete {filename}", key=f"delete_{fid}"):
                        try:
                            conn = connect_db()
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM files WHERE id=%s", (fid,))
                            cursor.execute("DELETE FROM shared_files WHERE file_id=%s", (fid,))
                            conn.commit()
                            conn.close()
                            os.remove(os.path.join(upload_folder, f"{filename}.enc"))
                            st.success("✅ File deleted.")
                        except Exception as e:
                            st.error(f"❌ Delete failed: {e}")
                with col3:
                    recipient = st.text_input(f"Share '{filename}' with:", key=f"share_input_{fid}")
                    if st.button(f"🔗 Share {filename}", key=f"share_btn_{fid}"):
                        if not recipient:
                            st.warning("⚠️ Enter a valid username to share.")
                        elif recipient == st.session_state.username:
                            st.warning("⚠️ You cannot share with yourself.")
                        else:
                            try:
                                conn = connect_db()
                                cursor = conn.cursor()
                                cursor.execute("SELECT * FROM users WHERE username=%s", (recipient,))
                                if cursor.fetchone():
                                    cursor.execute("""INSERT INTO shared_files (file_id, shared_by, shared_to, aes_key)
                                                      VALUES (%s, %s, %s, %s)""",
                                                   (fid, st.session_state.username, recipient, aes_key))
                                    conn.commit()
                                    st.success(f"✅ Shared with {recipient}.")
                                else:
                                    st.error("❌ User not found.")
                                conn.close()
                            except Exception as e:
                                st.error(f"❌ Share failed: {e}")
                st.markdown("---")
    else:
        st.warning("🔐 Login to access wallet.")

# --- Shared With Me ---
if menu == "Shared With Me":
    if st.session_state.logged_in:
        st.subheader("📩 Files Shared With You")
        conn = connect_db()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT sf.id, f.filename, f.category, sf.shared_by, sf.aes_key, f.id
                              FROM shared_files sf
                              JOIN files f ON sf.file_id = f.id
                              WHERE sf.shared_to = %s""", (st.session_state.username,))
            shared_files = cursor.fetchall()
            conn.close()

            if not shared_files:
                st.info("📭 No files shared with you.")
            else:
                for sid, filename, category, sender, aes_key, file_id in shared_files:
                    st.markdown(f"### 📄 {filename}")
                    st.markdown(f"""**Category:** {category}  
**Shared by:** {sender}  
**Shared Key:** `{aes_key}`  
""")
                    if st.button(f"⬇️ Download {filename}", key=f"shared_download_{sid}"):
                        try:
                            enc_path = os.path.join(upload_folder, f"{filename}.enc")
                            with open(enc_path, "rb") as f:
                                enc_data = f.read()
                            dec = decrypt_file(enc_data, aes_key)
                            st.download_button("📥 Download File", dec, file_name=filename, key=f"shared_dl_btn_{sid}")
                        except Exception:
                            st.error("❌ Decryption failed.")
                    st.markdown("---")
    else:
        st.warning("🔐 Login to view shared files.")

# --- Delete Account ---
if menu == "Delete Account":
    if st.session_state.logged_in:
        st.subheader("❌ Delete My Account")
        confirm = st.text_input("Type your username to confirm deletion")
        if confirm == st.session_state.username:
            if st.button("Delete My Account"):
                try:
                    conn = connect_db()
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM files WHERE owner=%s", (confirm,))
                    cursor.execute("DELETE FROM shared_files WHERE shared_by=%s OR shared_to=%s", (confirm, confirm))
                    cursor.execute("DELETE FROM users WHERE username=%s", (confirm,))
                    conn.commit()
                    conn.close()

                    for file in os.listdir(upload_folder):
                        if file.endswith(".enc"):
                            os.remove(os.path.join(upload_folder, file))

                    st.success("✅ Account and all files deleted.")
                    st.session_state.logged_in = False
                    st.session_state.username = ""
                except Exception as e:
                    st.error(f"❌ Error deleting account: {e}")
    else:
        st.warning("🔐 Login to delete account.")
