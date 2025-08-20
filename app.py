# app.py
import streamlit as st
import os
import hashlib
from encryptor import encrypt_file, decrypt_file
from db import connect_db, log_action
from datetime import datetime, timedelta
from key_manager import encrypt_aes_key, decrypt_aes_key
import re
import smtplib
from email.message import EmailMessage

# --- Config ---
st.set_page_config(page_title="Secure Vault", page_icon="🔐", layout="wide")

# --- Styles ---
st.markdown("""
<style>
.stButton > button {
    background-color: black;
    color: white;
    padding: 0.6em 0;
    font-weight: 600;
    width: 100%;
    border-radius: 6px;
    margin: 4px 0px;
}
.stButton > button:hover {
    background-color: #006699;
    color: #ffffff;
}
</style>
""", unsafe_allow_html=True)

# --- Session State ---
ss = st.session_state
ss.setdefault("logged_in", False)
ss.setdefault("username", "")
ss.setdefault("page", "Login")
ss.setdefault("pending_user", None)     # for MFA
ss.setdefault("otp", None)
ss.setdefault("otp_expiry", None)

# --- Upload Dir ---
upload_folder = "uploads"
os.makedirs(upload_folder, exist_ok=True)

# --- Helpers ---
def send_email(to_email: str, subject: str, body: str):
    cfg = st.secrets["email"]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f'{cfg.get("from_name","Secure Vault")} <{cfg["from_email"]}>'
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
        server.starttls()
        server.login(cfg["username"], cfg["password"])
        server.send_message(msg)

def gen_otp():
    import random
    return str(random.randint(100000, 999999))

def check_password_requirements(password):
    return {
        "At least 8 characters": len(password) >= 8,
        "Contains uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Contains lowercase letter": bool(re.search(r"[a-z]", password)),
        "Contains a digit": bool(re.search(r"\d", password)),
        "Contains a special character": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }

def get_client_ip():
    # Optional; Streamlit doesn’t expose real client IP in simple deployments
    return None

# --- Sidebar ---
st.sidebar.title("🔐 Secure Vault")
menu_options = [
    ("Register", "📝 Register"),
    ("Login", "🔐 Login"),
    ("Upload Document", "📄 Upload"),
    ("My Wallet", "💳 My Wallet"),
    ("Shared With Me", "📩 Shared With Me"),
    ("Activity Logs", "📊 Activity Logs"),
    ("Forgot Password", "🔁 Forgot Password"),
    ("Find Username", "🧭 Find Username"),
    ("Delete Account", "❌ Delete Account"),
    ("Logout", "🚪 Logout"),
]
for option, label in menu_options:
    if st.sidebar.button(label, use_container_width=True):
        ss.page = option

menu = ss.page
categories = ["Aadhaar", "PAN", "ID Proof", "Insurance", "School Marksheets", "College Certificates", "Asset Documents", "Other"]

# =========================
# Register
# =========================
if menu == "Register":
    st.subheader("📟 Create Account")
    user = st.text_input("Username")
    email = st.text_input("Email")
    pwd = st.text_input("Password", type="password")

    if pwd:
        st.markdown("### 🔐 Password Strength")
        for rule, passed in check_password_requirements(pwd).items():
            st.markdown(("✅ " if passed else "❌ ") + rule)

    if st.button("Create"):
        checks = check_password_requirements(pwd)
        if not all(checks.values()):
            st.error("❌ Please meet all password requirements.")
        elif not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.error("❌ Enter a valid email.")
        else:
            conn = connect_db()
            if conn:
                try:
                    cur = conn.cursor()
                    hashed = hashlib.sha256(pwd.encode()).hexdigest()
                    cur.execute(
                        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                        (user, email, hashed)
                    )
                    conn.commit()
                    st.success("✅ User registered!")
                except Exception as e:
                    st.error(f"❌ Error: username/email may already exist. {e}")
                finally:
                    conn.close()

# =========================
# Login + MFA
# =========================
if menu == "Login":
    st.subheader("🔑 Login")
    # Step 1: username/password
    if ss.pending_user is None:
        user = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        if st.button("Login"):
            conn = connect_db()
            if conn:
                try:
                    cur = conn.cursor()
                    hashed = hashlib.sha256(pwd.encode()).hexdigest()
                    cur.execute("SELECT email FROM users WHERE username=%s AND password=%s", (user, hashed))
                    row = cur.fetchone()
                    if row:
                        email = row[0]
                        # Generate OTP, send email
                        ss.otp = gen_otp()
                        ss.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                        ss.pending_user = user
                        try:
                            send_email(
                                email,
                                "Your Secure Vault OTP",
                                f"Hi {user},\n\nYour OTP is: {ss.otp}\nIt expires in 5 minutes.\n\n– Secure Vault"
                            )
                            st.info("📧 OTP sent to your registered email. Please enter it below.")
                        except Exception as e:
                            ss.pending_user = None
                            st.error(f"❌ Could not send OTP email: {e}")
                    else:
                        st.error("❌ Invalid credentials.")
                except Exception as e:
                    st.error(f"⚠️ Login error: {e}")
                finally:
                    conn.close()

    # Step 2: OTP entry
    if ss.pending_user is not None:
        st.write(f"Enter the OTP sent to **{ss.pending_user}**’s email")
        otp_in = st.text_input("OTP", max_chars=6)
        if st.button("Verify OTP"):
            if ss.otp and ss.otp_expiry and datetime.utcnow() < ss.otp_expiry and otp_in == ss.otp:
                ss.logged_in = True
                ss.username = ss.pending_user
                ss.pending_user = None
                ss.otp = None
                ss.otp_expiry = None
                st.success(f"🎉 Welcome, {ss.username}!")
                log_action(ss.username, "LOGIN_SUCCESS", None, get_client_ip())
            else:
                st.error("❌ Invalid or expired OTP. Try login again.")
                ss.pending_user = None
                ss.otp = None
                ss.otp_expiry = None

# =========================
# Logout
# =========================
if menu == "Logout":
    if ss.logged_in:
        ss.logged_in = False
        ss.username = ""
        st.success("🚪 Logged out successfully.")
    else:
        st.error("🚫 You are not logged in.")

# =========================
# Upload (AES-GCM + progress)
# =========================
if menu == "Upload Document":
    if ss.logged_in:
        st.subheader("📄 Upload & Encrypt Document")
        file = st.file_uploader("Choose document")
        category = st.selectbox("📂 Select Category", categories)
        key = st.text_input("🔐 Enter 16-char AES Key (keep this private!)", max_chars=16)
        if st.button("Upload"):
            if not file or not key:
                st.error("❌ File and AES Key are required.")
            elif len(key) != 16:
                st.error("❌ AES key must be exactly 16 characters.")
            else:
                try:
                    data = file.read()
                    progress = st.progress(0)
                    progress.progress(10)

                    enc_bytes = encrypt_file(data, key)
                    progress.progress(60)

                    enc_path = os.path.join(upload_folder, f"{file.name}.enc")
                    with open(enc_path, "wb") as f:
                        f.write(enc_bytes)
                    progress.progress(80)

                    conn = connect_db()
                    if conn:
                        cur = conn.cursor()
                        wrapped_key = encrypt_aes_key(key)  # bytes
                        cur.execute(
                            "INSERT INTO files (filename, category, owner, aes_key) VALUES (%s, %s, %s, %s)",
                            (file.name, category, ss.username, wrapped_key)
                        )
                        conn.commit()
                        conn.close()
                        progress.progress(100)
                        st.toast("✅ File uploaded & encrypted!", icon="✅")
                        log_action(ss.username, "UPLOAD", file.name, get_client_ip())
                except Exception as e:
                    st.error(f"🚫 Upload failed: {e}")
    else:
        st.warning("🔐 Login to upload.")

# =========================
# My Wallet (search + download/share/delete)
# =========================
if menu == "My Wallet":
    if ss.logged_in:
        st.subheader(f"💳 {ss.username}'s Wallet")

        conn = connect_db()
        rows = []
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT id, filename, category, upload_time, aes_key FROM files WHERE owner=%s",
                        (ss.username,))
            rows = cur.fetchall()
            conn.close()

        if not rows:
            st.info("🗂️ No documents uploaded yet.")
        else:
            # Search box
            q = st.text_input("🔍 Search by filename or category")
            if q:
                q_low = q.lower()
                rows = [r for r in rows if q_low in r[1].lower() or q_low in r[2].lower()]

            for fid, filename, category, time, wrapped_key in rows:
                st.markdown(f"### 📄 {filename}")
                st.markdown(f"**Category:** {category}  \n**Uploaded:** {time}")

                # Keep wrapped_key for re-share; derive plaintext for download
                try:
                    user_key = decrypt_aes_key(wrapped_key)
                except Exception:
                    user_key = None

                c1, c2 = st.columns([1, 1])
                with c1:
                    if st.button(f"📥 Download {filename}", key=f"download_{fid}"):
                        try:
                            enc_path = os.path.join(upload_folder, f"{filename}.enc")
                            with open(enc_path, "rb") as f:
                                enc_data = f.read()
                            dec = decrypt_file(enc_data, user_key)
                            st.download_button("📎 Download File", dec, file_name=filename, key=f"download_button_{fid}")
                            log_action(ss.username, "DOWNLOAD", filename, get_client_ip())
                        except Exception as e:
                            st.error(f"❌ Decryption failed: {e}")

                with c2:
                    if st.button(f"🗑 Delete {filename}", key=f"delete_{fid}"):
                        try:
                            conn = connect_db()
                            cur = conn.cursor()
                            cur.execute("DELETE FROM files WHERE id=%s", (fid,))
                            cur.execute("DELETE FROM shared_files WHERE file_id=%s", (fid,))
                            conn.commit()
                            conn.close()
                            try:
                                os.remove(os.path.join(upload_folder, f"{filename}.enc"))
                            except FileNotFoundError:
                                pass
                            st.success("✅ File deleted.")
                            log_action(ss.username, "DELETE", filename, get_client_ip())
                        except Exception as e:
                            st.error(f"❌ Delete failed: {e}")

                with st.container():
                    recipient = st.text_input(f"Share '{filename}' with (username):", key=f"share_input_{fid}")
                    if st.button(f"🔗 Share {filename}", key=f"share_btn_{fid}"):
                        if not recipient:
                            st.warning("⚠️ Enter a valid username to share.")
                        elif recipient == ss.username:
                            st.warning("⚠️ You cannot share with yourself.")
                        else:
                            try:
                                conn = connect_db()
                                cur = conn.cursor()
                                cur.execute("SELECT 1 FROM users WHERE username=%s", (recipient,))
                                if cur.fetchone():
                                    # Store wrapped key (NOT plaintext) in shared_files
                                    cur.execute(
                                        "INSERT INTO shared_files (file_id, shared_by, shared_to, aes_key) VALUES (%s, %s, %s, %s)",
                                        (fid, ss.username, recipient, wrapped_key)
                                    )
                                    conn.commit()
                                    st.success(f"✅ Shared with {recipient}.")
                                    log_action(ss.username, "SHARE", filename, get_client_ip())
                                else:
                                    st.error("❌ User not found.")
                                conn.close()
                            except Exception as e:
                                st.error(f"❌ Share failed: {e}")
                st.markdown("---")
    else:
        st.warning("🔐 Login to access wallet.")

# =========================
# Shared With Me
# =========================
if menu == "Shared With Me":
    if ss.logged_in:
        st.subheader("📩 Files Shared With You")
        conn = connect_db()
        if conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT sf.id, f.filename, f.category, sf.shared_by, sf.aes_key, f.id
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
                WHERE sf.shared_to = %s
            """, (ss.username,))
            shared_files = cur.fetchall()
            conn.close()

            if not shared_files:
                st.info("📭 No files shared with you.")
            else:
                for sid, filename, category, sender, wrapped_key, file_id in shared_files:
                    st.markdown(f"### 📄 {filename}")
                    st.markdown(f"**Category:** {category}  \n**Shared by:** {sender}")
                    if st.button(f"⬇️ Download {filename}", key=f"shared_download_{sid}"):
                        try:
                            user_key = decrypt_aes_key(wrapped_key)
                            enc_path = os.path.join(upload_folder, f"{filename}.enc")
                            with open(enc_path, "rb") as f:
                                enc_data = f.read()
                            dec = decrypt_file(enc_data, user_key)
                            st.download_button("📥 Download File", dec, file_name=filename, key=f"shared_dl_btn_{sid}")
                            log_action(ss.username, "DOWNLOAD", filename, get_client_ip())
                        except Exception as e:
                            st.error(f"❌ Decryption failed: {e}")
                    st.markdown("---")
    else:
        st.warning("🔐 Login to view shared files.")

# =========================
# Activity Logs
# =========================
if menu == "Activity Logs":
    if ss.logged_in:
        st.subheader("📊 Your Activity")
        conn = connect_db()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT action, filename, ts FROM audit_logs WHERE username=%s ORDER BY ts DESC LIMIT 200",
                        (ss.username,))
            logs = cur.fetchall()
            conn.close()
            if not logs:
                st.info("No activity yet.")
            else:
                for action, fn, ts in logs:
                    st.write(f"• **{ts}** — {action}" + (f" — *{fn}*" if fn else ""))
    else:
        st.warning("🔐 Login to see logs.")

# =========================
# Forgot Password (email OTP)
# =========================
if menu == "Forgot Password":
    st.subheader("🔁 Reset Password")
    step = st.radio("Step", ["Request OTP", "Verify & Reset"], horizontal=True)

    if step == "Request OTP":
        email = st.text_input("Registered Email")
        if st.button("Send OTP"):
            conn = connect_db()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT username FROM users WHERE email=%s", (email,))
                    row = cur.fetchone()
                    if not row:
                        st.error("❌ Email not found.")
                    else:
                        ss.otp = gen_otp()
                        ss.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                        ss.pending_user = row[0]  # store for reset
                        send_email(email, "Secure Vault Password Reset OTP",
                                   f"Your OTP is: {ss.otp}\nIt expires in 5 minutes.")
                        st.success("✅ OTP sent. Switch to 'Verify & Reset' tab.")
                except Exception as e:
                    st.error(f"❌ Could not send OTP: {e}")
                finally:
                    conn.close()

    else:  # Verify & Reset
        otp_in = st.text_input("Enter OTP", max_chars=6)
        new_pwd = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if not (ss.otp and ss.otp_expiry and datetime.utcnow() < ss.otp_expiry and otp_in == ss.otp):
                st.error("❌ Invalid/expired OTP.")
            elif not all(check_password_requirements(new_pwd).values()):
                st.error("❌ New password doesn’t meet requirements.")
            else:
                conn = connect_db()
                if conn:
                    try:
                        cur = conn.cursor()
                        hashed = hashlib.sha256(new_pwd.encode()).hexdigest()
                        cur.execute("UPDATE users SET password=%s WHERE username=%s", (hashed, ss.pending_user))
                        conn.commit()
                        st.success("✅ Password updated. You can login now.")
                        ss.otp = None; ss.otp_expiry = None; ss.pending_user = None
                    except Exception as e:
                        st.error(f"❌ Error updating password: {e}")
                    finally:
                        conn.close()

# =========================
# Find Username (by email)
# =========================
if menu == "Find Username":
    st.subheader("🧭 Find Username")
    email = st.text_input("Registered Email")
    if st.button("Send My Username"):
        conn = connect_db()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT username FROM users WHERE email=%s", (email,))
                row = cur.fetchone()
                if row:
                    try:
                        send_email(email, "Your Secure Vault Username", f"Your username is: {row[0]}")
                        st.success("✅ Username sent to your email.")
                    except Exception as e:
                        st.error(f"❌ Could not send email: {e}")
                else:
                    st.error("❌ Email not found.")
            finally:
                conn.close()

# =========================
# Delete Account
# =========================
if menu == "Delete Account":
    if ss.logged_in:
        st.subheader("❌ Delete My Account")
        confirm = st.text_input("Type your username to confirm deletion")
        if confirm and confirm != ss.username:
            st.warning("❌ You are not allowed to delete others' accounts.")
        elif confirm == ss.username and st.button("Delete My Account"):
            try:
                conn = connect_db()
                cur = conn.cursor()
                # gather user files to remove disk copies
                cur.execute("SELECT filename FROM files WHERE owner=%s", (confirm,))
                user_files = [r[0] for r in cur.fetchall()]

                cur.execute("DELETE FROM files WHERE owner=%s", (confirm,))
                cur.execute("DELETE FROM shared_files WHERE shared_by=%s OR shared_to=%s", (confirm, confirm))
                cur.execute("DELETE FROM users WHERE username=%s", (confirm,))
                conn.commit()
                conn.close()

                for fn in user_files:
                    p = os.path.join(upload_folder, f"{fn}.enc")
                    try:
                        os.remove(p)
                    except FileNotFoundError:
                        pass

                st.success("✅ Account and all files deleted.")
                log_action(confirm, "ACCOUNT_DELETED", None, get_client_ip())
                ss.logged_in = False
                ss.username = ""
            except Exception as e:
                st.error(f"❌ Error deleting account: {e}")
    else:
        st.warning("🔐 Login to delete account.")
