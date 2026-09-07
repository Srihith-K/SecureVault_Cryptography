import csv
import base64
from io import StringIO
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory,
    flash,
    Response,
    abort
)
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from crypto.master_key import (
    encrypt_private_key,
    decrypt_private_key
)
from crypto.user_keys import generate_user_keypair
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import urllib.request
import urllib.error
import json
import uuid
import secrets
import traceback
import re
import random
import hashlib
from datetime import datetime, timedelta
from database import db
from models import (
    User,
    File,
    FileVersion,
    Activity,
    FileAccessLog,
    SharedFile,
    SharedKey,
    PasswordReset,
    SecurityAlert
)
import models
from encryption import (
    encrypt_file,
    decrypt_file,
    calculate_file_hash,
    ENCRYPTED_FOLDER,
    DECRYPTED_FOLDER
)
from rsa_encryption import (
    encrypt_aes_key,
    decrypt_aes_key,
    generate_user_keypair,
    encrypt_aes_key_with_public_key,
    decrypt_aes_key_with_private_key
)
from crypto.digital_signature import sign_data, verify_signature
from storage import upload_to_b2, delete_from_b2, download_from_b2
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from sqlalchemy import or_

app = Flask(__name__)
load_dotenv()

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_NAME = os.getenv("SENDER_NAME")

def send_brevo_email(to_email, subject, body=None, html=None):
    url = "https://api.brevo.com/v3/smtp/email"

    data = {
        "sender": {
            "name": SENDER_NAME,
            "email": SENDER_EMAIL
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject
    }

    if html:
        data["htmlContent"] = html
    else:
        data["textContent"] = body or ""

    request = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise Exception(f"Brevo API Error {e.code}: {error_body}")

print("Brevo configured:", bool(BREVO_API_KEY))
print("Sender:", SENDER_EMAIL)
print("Name:", SENDER_NAME)

app.secret_key = os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(minutes=15)

# Base directory setup
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define absolute directory paths
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "decrypted")
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")
ENCRYPTED_KEYS_FOLDER = os.path.join(BASE_DIR, "encrypted_keys")

# Create required folders reliably using absolute paths
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_KEYS_FOLDER, exist_ok=True)

# ---------------- ALLOWED FILE EXTENSIONS ---------------- #

ALLOWED_EXTENSIONS = {
    # Documents
    "txt",
    "pdf",
    "doc",
    "docx",
    "odt",
    "rtf",

    # Spreadsheets
    "xls",
    "xlsx",
    "csv",
    "ods",

    # Presentations
    "ppt",
    "pptx",
    "odp",

    # Images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "bmp",
    "svg",
    "tiff",

    # Audio
    "mp3",
    "wav",
    "ogg",
    "m4a",
    "flac",

    # Video
    "mp4",
    "mkv",
    "avi",
    "mov",
    "webm",

    # Archives
    "zip",
    "rar",
    "7z",
    "tar",
    "gz",

    # Programming / Source Code
    "py",
    "java",
    "c",
    "cpp",
    "h",
    "hpp",
    "js",
    "jsx",
    "ts",
    "tsx",
    "html",
    "css",
    "json",
    "xml",
    "sql",
    "md"
}

# Helper function to check allowed file extensions
def allowed_file(filename):
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )

# ---------------- FILE INTEGRITY VERIFICATION ---------------- #

def verify_file_integrity(file, user_id):
    """
    Verifies that the encrypted file has not been modified.
    Returns True if verified, otherwise False.
    """

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        f"integrity_{file.id}.enc"
        )

    try:
        download_from_b2(
            file.encrypted_filename,
            encrypted_path
        )
    except Exception:
        file.integrity_status = "Missing"
        db.session.commit()
        return False

    if not os.path.exists(encrypted_path):

        file.integrity_status = "Missing"

        existing_alert = SecurityAlert.query.filter_by(
            file_id=file.id,
            alert_type="Integrity Failure",
            status="Open"
        ).first()

        if not existing_alert:
            alert = SecurityAlert(
                file_id=file.id,
                user_id=user_id,
                alert_type="Integrity Failure",
                severity="High",
                description=f"Encrypted file missing for '{file.filename}'."
            )
            db.session.add(alert)
            db.session.commit()

        activity = Activity(
            user_id=user_id,
            action="Security Alert: Encrypted File Missing",
            filename=file.filename
        )

        db.session.add(activity)
        db.session.commit()

        return False

    current_hash = calculate_file_hash(encrypted_path)

    if current_hash != file.file_hash:

        file.integrity_status = "Tampered"

        existing_alert = SecurityAlert.query.filter_by(
            file_id=file.id,
            alert_type="Integrity Failure",
            status="Open"
        ).first()

        if not existing_alert:
            alert = SecurityAlert(
                file_id=file.id,
                user_id=user_id,
                alert_type="Integrity Failure",
                severity="High",
                description=f"SHA-256 integrity verification failed for '{file.filename}'."
            )
            db.session.add(alert)
            db.session.commit()

        activity = Activity(
            user_id=user_id,
            action="Security Alert: File Integrity Verification Failed",
            filename=file.filename
        )

        db.session.add(activity)
        db.session.commit()

        return False

    file.integrity_status = "Verified"
    db.session.commit()

    return True

# ---------------- FILE ACCESS LOGGER ---------------- #
def log_file_access(user_id, owner_id, file, action):

    log = FileAccessLog(
        user_id=user_id,
        owner_id=owner_id,
        file_id=file.id,
        filename=file.filename,
        action=action,
        ip_address=request.remote_addr or "Unknown"
    )

    db.session.add(log)
    db.session.commit()

# -----------------------------
# OTP Generator
# -----------------------------
def generate_otp():
    return str(random.randint(100000, 999999))

def send_login_otp(email, otp):
    subject = "SecureVault Login OTP"

    body = f"""
Your One-Time Password (OTP) is: {otp}

This OTP is valid for 5 minutes.

If you did not request this login, ignore this email.

Regards,
SecureVault Team
"""

    send_brevo_email(
        to_email=email,
        subject=subject,
        body=body
    )

def send_share_email(
        receiver_email,
        receiver_name,
        sender_name,
        filename,
        expiry,
        encrypted_one_time_secret=None):

    subject = "SecureVault - File Shared With You"

    if expiry:
        expiry_text = expiry.strftime(
            "%d %B %Y %I:%M %p UTC"
        )
    else:
        expiry_text = "No expiry"

    if encrypted_one_time_secret:
        ciphertext_section = f"""
-------------------------------------

ONE-TIME ACCESS CIPHERTEXT

{encrypted_one_time_secret}

-------------------------------------

How to use:

1. Login to SecureVault.
2. Open "Shared Files".
3. Select this file.
4. Open the "Decrypt Secret" option.
5. Paste the ciphertext shown above.
6. SecureVault will decrypt and verify the
   one-time access secret.
7. The secret can only be used once.

IMPORTANT:
This ciphertext is intended only for you.
Do not share it with anyone else.

-------------------------------------
"""
    else:
        ciphertext_section = ""

    body = f"""
Hello {receiver_name},

A file has been securely shared with you.

-------------------------------------

Sender: {sender_name}

File: {filename}

Share Expiry: {expiry_text}

-------------------------------------
{ciphertext_section}

Please login to SecureVault to access the file.

Regards,

SecureVault Team
"""
    send_brevo_email(
        to_email=receiver_email,
        subject=subject,
        body=body
        )

def cleanup_expired_shares():

    expired = SharedFile.query.filter(
        SharedFile.expires_at.isnot(None),
        SharedFile.expires_at < datetime.utcnow(),
        SharedFile.is_active == True
    ).all()

    for share in expired:

        share.is_active = False

        SharedKey.query.filter_by(
            file_id=share.file_id,
            receiver_id=share.receiver_id
        ).delete()

        activity = Activity(
            user_id=share.sender_id,
            action="Expired Share Removed",
            filename=File.query.get(share.file_id).filename
        )

        db.session.add(activity)

    db.session.commit()

# -----------------------------
# One-Time Secret Helpers
# -----------------------------
def generate_one_time_secret():
    """
    Generate a cryptographically secure 6-digit secret.
    """
    return str(secrets.randbelow(900000) + 100000)

def hash_one_time_secret(secret):
    """
    Store only the SHA-256 hash of the one-time secret.
    """
    return hashlib.sha256(
        secret.encode("utf-8")
    ).hexdigest()

# App configuration
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

bcrypt = Bcrypt(app)
db.init_app(app)
migrate = Migrate(app, db)


# ---------------- SESSION REFRESH ---------------- #

@app.before_request
def refresh_session():

    session.permanent = True
    session.modified = True

    cleanup_expired_shares()


# ---------------- HOME ---------------- #

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        remember = request.form.get("remember_me")

        user = User.query.filter_by(email=email).first()

        if user and not user.email_verified:
            flash(
                "Please verify your email before logging in.",
                "warning"
            )
            return redirect(url_for("login"))

        if user:
            # Check if the Account is Locked
            if user and user.locked_until:
                if datetime.utcnow() < user.locked_until:
                    flash(
                        "Account temporarily locked. Please try again later.",
                        "danger"
                    )
                    return redirect("/login")

            if bcrypt.check_password_hash(user.password, password):
                if remember:
                    app.permanent_session_lifetime = timedelta(days=30)
                    session.permanent = True
                else:
                    app.permanent_session_lifetime = timedelta(minutes=15)
                    session.permanent = True
                
                # Reset After Successful Login
                user.failed_attempts = 0
                user.locked_until = None
                activity = Activity(
                    user_id=user.id,
                    action="Successful Login",
                    filename=""
                    )
                db.session.add(activity)
                
                otp = generate_otp()
                user.otp = otp
                user.otp_created_at = datetime.utcnow()
                db.session.commit()

                # Send OTP email
                send_login_otp(user.email, otp)

                # Temporary session
                session["pending_user_id"] = user.id
                return redirect(url_for("verify_otp"))
            else:
                # Handle Wrong Passwords
                user.failed_attempts += 1

                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                    user.failed_attempts = 0

                    # Create Security Alert
                    alert = SecurityAlert(
                        user_id=user.id,
                        alert_type="Multiple Failed Login Attempts",
                        description=(
                            f"User {user.email} reached the maximum "
                            "number of failed login attempts. "
                            "Account has been temporarily locked."
                            ),
                            severity="High",
                            status="Open")

                    db.session.add(alert)

                    flash(
                        "Too many failed attempts. Account locked for 5 minutes.",
                        "danger"
                        )

                else:
                    flash(
                        f"Incorrect password. Attempt {user.failed_attempts}/5",
                        "warning"
                    )

                # Record Failed Login
                activity = Activity(
                    user_id=user.id,
                    action="Failed Login",
                    filename=""
                )

                db.session.add(activity)
                db.session.commit()

                return redirect("/login")
        else:
            flash("User not found.", "warning")
            return redirect(url_for("login"))

    return render_template("login.html")


# ---------------- VERIFY OTP ROUTE ---------------- #

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["pending_user_id"])

    if request.method == "POST":

        entered_otp = request.form["otp"]

        if user.otp != entered_otp:

            flash(
                "Invalid OTP.",
                "danger"
            )

            return redirect(url_for("verify_otp"))

        # OTP Expiry Check
        if datetime.utcnow() > user.otp_created_at + timedelta(minutes=5):

            flash(
                "OTP has expired.",
                "danger"
            )

            return redirect(url_for("verify_otp"))

        # Clear OTP
        user.otp = None
        user.otp_created_at = None

        db.session.commit()

        # Login Complete
        session.pop("pending_user_id")
        session["user_id"] = user.id
        session["user_name"] = user.name
        session["is_admin"] = user.is_admin

        # Record Successful Login
        activity = Activity(
            user_id=user.id,
            action="Successful Login",
            filename=""
            )
        db.session.add(activity)
        db.session.commit()

        flash(
            "Login Successful.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html")


@app.route("/logout")
def logout():

    if "user_id" in session:

        activity = Activity(
            user_id=session["user_id"],
            action="Logout",
            filename=""
        )

        db.session.add(activity)
        db.session.commit()

    session.clear()

    return redirect(url_for("login"))

# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    sort = request.args.get("sort", "date")
    file_type = request.args.get("file_type", "")

    query = File.query.filter_by(
        owner_id=session["user_id"],
        is_deleted=False
    )

    if file_type:
        query = query.filter(File.file_type == file_type)

    if sort == "name":
        query = query.order_by(File.filename.asc())
    elif sort == "size":
        query = query.order_by(File.file_size.desc())
    elif sort == "downloads":
        query = query.order_by(File.download_count.desc())
    else:
        query = query.order_by(File.upload_date.desc())
    
    files = query.all()
    total_files = len(files)

    # Calculate Total Storage (Bytes)
    total_storage = sum(file.file_size or 0 for file in files)

    # Get current user
    user = User.query.get(session["user_id"])

    # Keep storage_used synchronized
    user.storage_used = total_storage
    db.session.commit()

    # Calculate remaining storage
    remaining_storage = user.storage_limit - user.storage_used
    if remaining_storage < 0:
        remaining_storage = 0

    # Calculate storage percentage
    storage_percentage = round(
        (user.storage_used / user.storage_limit) * 100,
        1
    )
    if storage_percentage > 100:
        storage_percentage = 100

    # Convert storage used to readable format
    if user.storage_used >= 1024 * 1024 * 1024:
        storage_used = f"{user.storage_used / (1024*1024*1024):.2f} GB"
    elif user.storage_used >= 1024 * 1024:
        storage_used = f"{user.storage_used / (1024*1024):.2f} MB"
    elif user.storage_used >= 1024:
        storage_used = f"{user.storage_used / 1024:.2f} KB"
    else:
        storage_used = f"{user.storage_used} B"

    # Convert storage limit
    if user.storage_limit >= 1024 * 1024 * 1024:
        storage_limit = f"{user.storage_limit / (1024*1024*1024):.2f} GB"
    else:
        storage_limit = f"{user.storage_limit / (1024*1024):.2f} MB"

    # Convert remaining storage
    if remaining_storage >= 1024 * 1024 * 1024:
        remaining_storage = f"{remaining_storage / (1024*1024*1024):.2f} GB"
    elif remaining_storage >= 1024 * 1024:
        remaining_storage = f"{remaining_storage / (1024*1024):.2f} MB"
    elif remaining_storage >= 1024:
        remaining_storage = f"{remaining_storage / 1024:.2f} KB"
    else:
        remaining_storage = f"{remaining_storage} B"
    
    activities = Activity.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        Activity.timestamp.desc()
    ).limit(5).all()

    is_admin = user.is_admin
    
    return render_template(
        "dashboard.html",
        files=files,
        activities=activities,
        total_files=total_files,
        storage_used=storage_used,
        storage_percentage=storage_percentage,
        storage_limit=storage_limit,
        remaining_storage=remaining_storage,
        user_name=session["user_name"],
        is_admin=is_admin
    )


# ---------------- SECURITY DASHBOARD ---------------- #

@app.route("/security-dashboard")
def security_dashboard():
    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    # ---------------- FILE STATISTICS ---------------- #
    total_files = File.query.filter_by(
        owner_id=user.id,
        is_deleted=False
    ).count()

    total_shared = SharedFile.query.filter_by(
        sender_id=user.id
    ).count()

    deleted_files = File.query.filter_by(
        owner_id=user.id,
        is_deleted=True
    ).count()

    # ---------------- STORAGE USED ---------------- #
    files = File.query.filter_by(
        owner_id=user.id,
        is_deleted=False
    ).all()

    storage_used = sum(file.file_size or 0 for file in files)

    storage_used_mb = round(
        storage_used / (1024 * 1024),
        2
    )

    # ---------------- CRYPTOGRAPHY STATISTICS ---------------- #
    encrypted_files = File.query.filter_by(
        owner_id=user.id,
        is_deleted=False
    ).count()
    signed_files = File.query.filter(
        File.owner_id == user.id,
        File.signature.isnot(None)
    ).count()
    verified_files = File.query.filter_by(
        owner_id=user.id,
        signature_verified=True
    ).count()

    verified_files = File.query.filter_by(
        integrity_status="Verified"
    ).count()
    tampered_files = File.query.filter_by(
        integrity_status="Tampered"
    ).count()
    missing_files = File.query.filter_by(
        integrity_status="Missing"
    ).count()

    # ---------------- RECENT ACTIVITY ---------------- #
    recent_logs = Activity.query.filter_by(
        user_id=user.id
    ).order_by(
        Activity.timestamp.desc()
    ).limit(5).all()

    # ---------------- SECURITY SCORE ---------------- #
    security_score = 0

    if user.email_verified:
        security_score += 20

    if user.two_factor_enabled:
        security_score += 20

    # Password Hashing
    security_score += 20

    # AES + RSA
    security_score += 20

    # Digital Signature
    security_score += 20

    return render_template(
        "security_dashboard.html",

        user=user,

        total_files=total_files,
        total_shared=total_shared,
        deleted_files=deleted_files,
        storage_used_mb=storage_used_mb,

        encrypted_files=encrypted_files,
        signed_files=signed_files,
        verified_files=verified_files,
        tampered_files=tampered_files,
        missing_files=missing_files,

        recent_logs=recent_logs,

        security_score=security_score
    )


# ---------------- FILE DETAILS ---------------- #

@app.route("/file/<int:file_id>")
def file_details(file_id):
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect("/login")

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"]
    ).first_or_404()

    return render_template(
        "file_details.html",
        file=file
    )


# ---------------- FILE VERSIONS ---------------- #

@app.route("/file/<int:file_id>/versions")
def file_versions(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"]
    ).first()

    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    versions = FileVersion.query.filter_by(
        file_id=file.id
    ).order_by(
        FileVersion.version_number.desc()
    ).all()

    return render_template(
        "file_versions.html",
        file=file,
        versions=versions
    )


# ---------------- DOWNLOAD VERSION ---------------- #

@app.route("/download-version/<int:version_id>")
def download_version(version_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    version = FileVersion.query.join(File).filter(
        FileVersion.id == version_id,
        File.owner_id == session["user_id"]
    ).first()

    if not version:
        flash("Version not found.", "danger")
        return redirect(url_for("dashboard"))

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        f"version_{version.id}.enc"
    )
    try:
        download_from_b2(
            version.encrypted_filename,
            encrypted_path
        )
    except Exception:
        flash("Encrypted file not found in cloud storage.", "danger")
        return redirect(url_for("dashboard"))

    current_hash = calculate_file_hash(encrypted_path)
    if current_hash != version.sha256_hash:
        flash(
            "Integrity verification failed! The encrypted file version has been modified.",
            "danger"
        )
        return redirect(url_for("dashboard"))

    key_path = os.path.join(
        ENCRYPTED_KEYS_FOLDER,
        f"version_{version.id}.key.enc"
    )
    try:
        download_from_b2(
            version.encrypted_key,
            key_path
        )
    except Exception:
        flash("Encrypted key not found in cloud storage.", "danger")
        return redirect(url_for("dashboard"))

    with open(key_path, "rb") as key_file:
        encrypted_aes_key = key_file.read()

    aes_key = decrypt_aes_key(encrypted_aes_key)

    decrypted_path = decrypt_file(
        encrypted_path,
        aes_key
    )

    activity = Activity(
        user_id=session["user_id"],
        action=f"Downloaded Version {version.version_number}",
        filename=version.filename
    )
    db.session.add(activity)
    db.session.commit()

    return send_from_directory(
        DECRYPTED_FOLDER,
        os.path.basename(decrypted_path),
        as_attachment=True,
        download_name=version.filename
    )


# ---------------- PREVIEW ---------------- #

@app.route("/preview/<int:file_id>")
def preview_file(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"]
    ).first_or_404()

    return render_template(
        "preview.html",
        file=file
    )


# ---------------- RECYCLE BIN ---------------- #

@app.route("/recycle-bin")
def recycle_bin():

    if "user_id" not in session:
        return redirect(url_for("login"))

    deleted_files = File.query.filter_by(
        owner_id=session["user_id"],
        is_deleted=True
    ).order_by(File.deleted_at.desc()).all()

    return render_template(
        "recycle_bin.html",
        deleted_files=deleted_files,
        user_name=session["user_name"],
        is_admin=session.get("is_admin", False)
    )


# ---------------- RESTORE FILE ---------------- #

@app.route("/restore/<int:file_id>")
def restore(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"]
    ).first()

    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("recycle_bin"))

    # Restore file
    file.is_deleted = False
    file.deleted_at = None
    file.deleted_by = None

    # Update storage usage
    user = User.query.get(session["user_id"])
    user.storage_used += file.file_size

    # Activity log
    activity = Activity(
        user_id=session["user_id"],
        action="Restored File",
        filename=file.filename
    )

    db.session.add(activity)

    db.session.commit()

    flash("File restored successfully.", "success")

    return redirect(url_for("recycle_bin"))


# ---------------- DELETE FOREVER ---------------- #

@app.route("/delete-forever/<int:file_id>")
def delete_forever(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"],
        is_deleted=True
    ).first()

    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("recycle_bin"))

    # Delete encrypted file and AES key from B2
    try:
        if file.encrypted_filename:
            delete_from_b2(file.encrypted_filename)

        if file.aes_key_filename:
            delete_from_b2(file.aes_key_filename)
    except Exception as e:
        print("B2 deletion error:", e)
        flash("Unable to delete the file from cloud storage.", "danger")
        return redirect(url_for("recycle_bin"))

    log_file_access(
        session["user_id"],
        file.owner_id,
        file,
        "Delete"
    )

    activity = Activity(
        user_id=session["user_id"],
        action="Deleted Permanently",
        filename=file.filename
    )

    db.session.add(activity)

    db.session.delete(file)

    db.session.commit()

    flash(
        "File permanently deleted.",
        "success"
    )

    return redirect(url_for("recycle_bin"))


# ---------------- PROFILE ---------------- #

@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect("/login")

    user = User.query.get_or_404(session["user_id"])

    total_files = File.query.filter_by(owner_id=user.id).count()

    storage = db.session.query(
        db.func.sum(File.file_size)
    ).filter_by(
        owner_id=user.id
    ).scalar() or 0

    activities = Activity.query.filter_by(
        user_id=user.id
    ).count()

    return render_template(
        "profile.html",
        user=user,
        total_files=total_files,
        storage=storage,
        activities=activities
    )


# ---------------- EDIT PROFILE ---------------- #

@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():

    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    user = User.query.get_or_404(session["user_id"])

    if request.method == "POST":

        name = request.form["name"].strip()

        if name == "":
            flash("Name cannot be empty.", "danger")
            return redirect(url_for("edit_profile"))

        user.name = name

        picture = request.files.get("profile_picture")

        if picture and picture.filename != "":

            filename = secure_filename(picture.filename)

            unique_filename = str(uuid.uuid4()) + "_" + filename

            picture.save(
                os.path.join(
                    app.static_folder,
                    "profile_pictures",
                    unique_filename
                )
            )

            user.profile_picture = unique_filename

        db.session.commit()

        # Update session name
        session["user_name"] = user.name

        activity = Activity(
            user_id=user.id,
            action="Updated Profile",
            filename=""
        )

        db.session.add(activity)
        db.session.commit()

        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template(
        "edit_profile.html",
        user=user
    )


# ---------------- CHANGE PASSWORD ---------------- #

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect("/login")

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        valid, message = is_strong_password(new_password)
        if not valid:
            flash(message, "danger")
            return redirect(url_for("change_password"))
        confirm_password = request.form["confirm_password"]

        # Check current password
        if not bcrypt.check_password_hash(user.password, current_password):
            flash("Current password is incorrect.", "danger")
            return redirect("/change-password")

        # Check new passwords match
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect("/change-password")

        # Hash new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.password = hashed_password
        db.session.commit()

        flash("Password changed successfully.", "success")
        return redirect("/profile")

    return render_template("change_password.html")


# ---------------- UPLOAD ---------------- #

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file and uploaded_file.filename != "":
            if not allowed_file(uploaded_file.filename):
                flash("File type not allowed.", "danger")
                return redirect(url_for("upload"))

            filename = secure_filename(uploaded_file.filename)
            unique_filename = str(uuid.uuid4())
            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                unique_filename + "_" + filename
                )
            uploaded_file.save(filepath)
            file_size = os.path.getsize(filepath)

            # Get current user
            user = User.query.get(session["user_id"])
            # Check storage limit
            if user.storage_used + file_size > user.storage_limit:

                # Delete temporarily uploaded file
                os.remove(filepath)

                flash(
                    "Storage limit exceeded. Please delete some files before uploading.",
                    "danger"
                )

                return redirect(url_for("upload"))

            # Encrypt file and the corresponding AES key
            encrypted_path, aes_key = encrypt_file(filepath)
            file_hash = calculate_file_hash(encrypted_path)
            signature = sign_data(file_hash.encode())
            print("Encrypted Path:", encrypted_path)
            print("File Hash:", file_hash)
            encrypted_aes_key = encrypt_aes_key(aes_key)
            key_filename = filename + ".key.enc"
            key_path = os.path.join(
                BASE_DIR,
                "encrypted_keys",
                key_filename
            )
            
            with open(key_path, "wb") as key_file:
                key_file.write(encrypted_aes_key)

            encrypted_filename = os.path.basename(encrypted_path)

            existing_file = File.query.filter_by(
                owner_id=session["user_id"],
                filename=uploaded_file.filename,
                is_deleted=False
            ).first()

            if not existing_file:
                new_file = File(
                    owner_id=session["user_id"],
                    filename=uploaded_file.filename,
                    encrypted_filename=encrypted_filename,
                    aes_key_filename=key_filename,
                    file_hash=file_hash,
                    signature=signature,
                    signature_verified=True,
                    signature_algorithm="RSA-2048",
                    file_size=file_size,
                    file_type=os.path.splitext(filename)[1].lower(),
                    download_count=0,
                    encryption_algorithm="AES-256 + RSA-2048",
                    integrity_status="Verified"
                )
                db.session.add(new_file)
                db.session.commit()

                # ---------------- B2 PERMANENT STORAGE ---------------- #
                b2_file_object = (
                    f"users/{session['user_id']}/"
                    f"files/{new_file.id}/"
                    f"versions/1/file.enc"
                    )

                b2_key_object = (
                    f"users/{session['user_id']}/"f"files/{new_file.id}/"
                    f"versions/1/key.enc"

                    )

                upload_to_b2(
                    encrypted_path,
                    b2_file_object
                    )

                upload_to_b2(
                    key_path,
                    b2_key_object

                    )

                encrypted_filename = b2_file_object
                key_filename = b2_key_object
                new_file.encrypted_filename = b2_file_object
                new_file.aes_key_filename = b2_key_object
                db.session.commit()
                print("====================================")
                print("B2 PERMANENT UPLOAD SUCCESS")
                print("File:", b2_file_object)
                print("Key:", b2_key_object)
                print("====================================")

                version = FileVersion(
                    file_id=new_file.id,
                    version_number=1,
                    filename=new_file.filename,
                    encrypted_filename=new_file.encrypted_filename,
                    encrypted_key=key_filename,
                    sha256_hash=new_file.file_hash,
                    file_size=new_file.file_size
                )
                db.session.add(version)
                db.session.commit()

                log_file_access(
                    user_id=session["user_id"],
                    owner_id=session["user_id"],
                    file=new_file,
                    action="Upload"
                )
            else:
                latest_version = FileVersion.query.filter_by(
                    file_id=existing_file.id
                ).order_by(
                    FileVersion.version_number.desc()
                ).first()

                next_version = 1
                if latest_version:
                    next_version = latest_version.version_number + 1

                # Upload version to B2
                b2_file_object = (
                    f"users/{session['user_id']}/"
                    f"files/{existing_file.id}/"
                    f"versions/{next_version}/file.enc"
                    )

                b2_key_object = (
                    f"users/{session['user_id']}/"
                    f"files/{existing_file.id}/"
                    f"versions/{next_version}/key.enc"
                    )

                upload_to_b2(
                    encrypted_path,
                    b2_file_object
                    )

                upload_to_b2(
                    key_path,
                    b2_key_object
                    )
                version = FileVersion(
                    file_id=existing_file.id,
                    version_number=next_version,
                    filename=existing_file.filename,
                    encrypted_filename=b2_file_object,
                    encrypted_key=b2_key_object,
                    sha256_hash=file_hash,
                    file_size=file_size
                    )

                existing_file.encrypted_filename = b2_file_object
                existing_file.aes_key_filename = b2_key_object
                db.session.add(version)

                existing_file.file_hash = file_hash
                existing_file.signature = signature
                existing_file.signature_verified = True
                existing_file.signature_algorithm = "RSA-2048"
                existing_file.file_size = file_size
                existing_file.upload_date = datetime.utcnow()

                db.session.commit()

                log_file_access(
                    user_id=session["user_id"],
                    owner_id=session["user_id"],
                    file=existing_file,
                    action="Upload"
                )

            # Increase used storage
            user.storage_used += file_size
            activity = Activity(
                user_id=session["user_id"],
                action="Uploaded",
                filename=filename
            )
            db.session.add(activity)
            db.session.commit()
            flash("File uploaded successfully!", "success")
            return redirect(url_for("dashboard"))

    return render_template("upload.html")

def is_strong_password(password):
    """
    Returns (True, "") if the password is strong,
    otherwise returns (False, error_message).
    """

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."

    return True, ""

# ---------------- REGISTER ---------------- #

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        valid, message = is_strong_password(password)
        if not valid:
            flash(message, "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return "<h3>Email already registered. Please use another email.</h3>"

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        
        token = secrets.token_urlsafe(32)
        
        public_key, private_key = generate_user_keypair()
        encrypted_private_key = encrypt_private_key(
            private_key
        )

        user = User(
            name=name,
            email=email,
            password=hashed_password,
            email_verified=False,
            verification_token=token,
            storage_limit=1073741824,
            storage_used=0,
            public_key=public_key,
            private_key=encrypted_private_key
        )

        db.session.add(user)
        db.session.commit()
        
        verification_link = url_for(
            "verify_email",
            token=token,
            _external=True
            )
        
        email_body = f"""
Hello {name},

Welcome to SecureVault.

Please verify your email by clicking the link below:{verification_link}

Regards,
SecureVault Team
"""
        try:
            send_brevo_email(
                to_email=email,
                subject="Verify Your SecureVault Account",
                body=email_body
            )

            flash(
                "Registration successful. Please check your email to verify your account.",
                "success"
            )
        except Exception as e:
            print("=" * 50)
            print("BREVO EMAIL ERROR")
            print(e)
            traceback.print_exc()
            print("=" * 50)

            flash(
                f"Email Error: {e}",
                "danger"
            )
        return redirect(url_for("login"))
        
    return render_template("register.html")


# ---------------- VERIFY EMAIL ---------------- #
@app.route("/verify-email/<token>")
def verify_email(token):

    user = User.query.filter_by(
        verification_token=token
    ).first()

    if user is None:
        flash(
            "Invalid or expired verification link.",
            "danger"
        )
        return redirect(url_for("login"))

    user.email_verified = True
    user.verification_token = None

    db.session.commit()

    flash(
        "Your email has been verified successfully. You can now log in.",
        "success"
    )

    return redirect(url_for("login"))


# ---------------- FORGOT PASSWORD ---------------- #
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"].strip()

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("No account found with that email.", "danger")
            return redirect(url_for("forgot_password"))

        # Remove Expired Tokens Automatically
        PasswordReset.query.filter(
            PasswordReset.expires_at < datetime.utcnow()
        ).delete()
        db.session.commit()

        # Delete old unused reset tokens
        PasswordReset.query.filter_by(
            user_id=user.id,
            used=False
        ).delete()

        # Generate secure token
        token = secrets.token_urlsafe(32)

        # Save token
        reset = PasswordReset(
            user_id=user.id,
            token=token,
            expires_at=datetime.utcnow() + timedelta(minutes=30)
        )

        db.session.add(reset)
        db.session.commit()

        # Create reset link
        reset_link = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        # Send email (HTML Email)
        email_html = render_template(
            "reset_email.html",
            user=user,
            reset_link=reset_link
            )

        print("Sending email to:", user.email)

        try:
            send_brevo_email(
                to_email=user.email,
                subject="SecureVault Password Reset",
                html=email_html
                )
            print("Brevo email sent successfully")

            flash(
        "A password reset link has been sent to your email.",
        "success"
    )
        except Exception as e:
            print("=" * 50)
            print("EMAIL ERROR")
            print(e)
            traceback.print_exc()
            print("=" * 50)

            flash(
                f"Email Error: {e}",
                "danger"
            )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    reset = PasswordReset.query.filter_by(
        token=token,
        used=False
    ).first()

    if reset is None:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for("login"))

    if datetime.utcnow() > reset.expires_at:
        flash("This password reset link has expired.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.get(reset.user_id)

    if request.method == "POST":
        password = request.form["password"]
        valid, message = is_strong_password(password)
        if not valid:
            flash(message, "danger")
            return redirect(url_for("reset_password", token=token))
        confirm = request.form["confirm_password"]

        # Add Password Strength Validation
        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )
            return redirect(url_for("reset_password", token=token))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password", token=token))

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        user.password = hashed_password
        
        # Improve Security by Invalidating All Previous Tokens
        PasswordReset.query.filter_by(
            user_id=user.id,
            used=False
        ).update({"used": True})
        db.session.commit()

        activity = Activity(
            user_id=user.id,
            action="Password Reset",
            filename=""
        )
        
        db.session.add(activity)
        db.session.commit()

        # Send confirmation email
        email_body = f"""
Hello {user.name},

Your SecureVault password has been changed successfully.

If you made this change, no further action is required.

If you did NOT change your password, please contact the administrator immediately.

Regards,
SecureVault Team
"""
        send_brevo_email(
            to_email=user.email,
            subject="Your SecureVault Password Has Been Changed",
            body=email_body
        )

        flash(
            "Password reset successfully. Please login.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template(
        "reset_password.html",
        token=token
    )


# ---------------- DOWNLOAD & DECRYPT ---------------- #

@app.route("/download/<path:filename>")
def download(filename):
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    file = File.query.filter_by(
        encrypted_filename=filename,
        owner_id=session["user_id"]
    ).first()

    if file is None:
        return "File not found or access denied.", 404
    
    if not verify_file_integrity(
        file,
        session["user_id"]
    ):

        flash(
            "Integrity verification failed.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    log_file_access(
        session["user_id"],
        file.owner_id,
        file,
        "Download"
    )

    activity = Activity(
        user_id=session["user_id"],
        action="Downloaded",
        filename=file.filename
    )
    db.session.add(activity)

    file.download_count += 1
    file.last_download = datetime.utcnow()

    db.session.commit()

    # Download encrypted file from B2
    b2_file_path = os.path.join(
    BASE_DIR,
    "encrypted",
    os.path.basename(filename)
)
    download_from_b2(
    file.encrypted_filename,
    b2_file_path
)
    return send_from_directory(
    ENCRYPTED_FOLDER,
    os.path.basename(filename),
    as_attachment=True
)

@app.route("/verify-share-password/<int:file_id>", methods=["GET", "POST"])
def verify_share_password(file_id):

    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect("/login")

    shared = SharedFile.query.filter_by(
        file_id=file_id,
        receiver_id=session["user_id"]
    ).first_or_404()

    if request.method == "POST":

        entered_password = request.form["share_password"]

        if check_password_hash(
            shared.share_password_hash,
            entered_password
        ):

            session[f"share_verified_{file_id}"] = True

            return redirect(
                url_for(
                    "shared_download",
                    file_id=file_id
                )
            )

        flash(
            "Incorrect share password.",
            "danger"
        )

    return render_template(
        "verify_share_password.html",
        shared=shared
    )

@app.route("/decrypt-secret/<int:file_id>", methods=["GET", "POST"])
def decrypt_secret(file_id):

    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect("/login")

    # Find the shared file belonging to the current receiver
    shared = SharedFile.query.filter_by(
        file_id=file_id,
        receiver_id=session["user_id"]
    ).first()

    if shared is None:
        flash("You do not have access to this shared file.", "danger")
        return redirect("/shared-files")

    # Check whether the owner has revoked the share
    if not shared.is_active:
        flash(
            "This shared file has been revoked by the owner.",
            "danger"
        )
        return redirect("/shared-files")

    # Check share expiry
    if shared.expires_at is not None:
        if datetime.utcnow() > shared.expires_at:
            flash(
                "This shared file has expired.",
                "danger"
            )
            return redirect("/shared-files")

    # Check whether the one-time secret was already used
    if shared.one_time_secret_used:
        flash(
            "The one-time access secret has already been used.",
            "danger"
        )
        return redirect("/shared-files")

    if request.method == "POST":

        ciphertext = request.form.get(
            "ciphertext",
            ""
        ).strip()

        if not ciphertext:
            flash(
                "Please enter the ciphertext.",
                "danger"
            )
            return redirect(request.url)

        try:

            # Convert Base64 ciphertext back to bytes
            encrypted_secret = base64.b64decode(
                ciphertext,
                validate=True
            )

            # Get receiver
            receiver = User.query.get(
                session["user_id"]
            )

            if receiver is None:
                flash(
                    "User account not found.",
                    "danger"
                )
                return redirect("/login")

            # Decrypt using receiver's private key
            private_key = decrypt_private_key(
                receiver.private_key
            )

            decrypted_secret = decrypt_aes_key_with_private_key(
                encrypted_secret,
                private_key
            )

            # Convert bytes → string
            one_time_secret = decrypted_secret.decode(
                "utf-8"
            )

            # Hash decrypted secret
            secret_hash = hash_one_time_secret(
                one_time_secret
            )

            # Compare with stored hash
            if secret_hash != shared.one_time_secret_hash:
                flash(
                    "Invalid ciphertext.",
                    "danger"
                )
                return redirect(request.url)

            # Mark secret as used
            shared.one_time_secret_used = True

            db.session.commit()

            # Store successful authorization temporarily
            session[
                f"secret_verified_{file_id}"
            ] = True

            flash(
                "Secret verified successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "shared_download",
                    file_id=file_id
                )
            )

        except Exception as e:

            print(
                "Secret decryption error:",
                e
            )

            flash(
                "Unable to decrypt the ciphertext.",
                "danger"
            )

            return redirect(request.url)

    file = File.query.get_or_404(file_id)

    return render_template(
        "decrypt_secret.html",
        shared=shared,
        file=file
    )

@app.route("/shared-download/<int:file_id>")
def shared_download(file_id):

    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect("/login")

    # Verify sharing permission
    shared = SharedFile.query.filter_by(
        file_id=file_id,
        receiver_id=session["user_id"]
    ).first()

    if shared is None:
        flash("Access denied.", "danger")
        return redirect("/shared-files")

    # Check if access has been revoked
    if not shared.is_active:
        flash(
            "This shared file has been revoked by the owner.",
            "danger"
        )
        return redirect("/shared-files")

    # Check whether the share has expired
    if shared.expires_at is not None:
        if datetime.utcnow() > shared.expires_at:
            flash(
                "This shared file has expired.",
                "danger"
            )
            return redirect("/shared-files")

    # One-time secret must be verified before download
    if not session.get(f"secret_verified_{file_id}", False):
        flash(
            "Please decrypt and verify the one-time secret first.",
            "warning"
        )
        return redirect(
            url_for(
                "decrypt_secret",
                file_id=file_id
            )
        )

    file = File.query.get_or_404(file_id)

    if not verify_file_integrity(
        file,
        session["user_id"]
    ):

        flash(
            "Integrity verification failed.",
            "danger"
        )

        return redirect("/shared-files")

    # Get receiver's encrypted AES key
    shared_key = SharedKey.query.filter_by(
        file_id=file.id,
        receiver_id=session["user_id"]
    ).first()

    if shared_key is None:
        flash("Encryption key not found.", "danger")
        return redirect("/shared-files")

    # Get current user
    receiver = User.query.get(session["user_id"])

    # Decrypt AES key using receiver's private key
    private_key = decrypt_private_key(
        receiver.private_key
    )
    aes_key = decrypt_aes_key_with_private_key(
        shared_key.encrypted_aes_key,
        private_key
    )

    # Download encrypted file from B2
    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        f"shared_{file.id}.enc"
    )
    download_from_b2(
        file.encrypted_filename,
        encrypted_path
    )

    # Decrypt file
    decrypted_path = decrypt_file(
        encrypted_path,
        aes_key
    )

    log_file_access(
        session["user_id"],
        file.owner_id,
        file,
        "Shared Download"
    )

    # Activity Log
    activity = Activity(
        user_id=session["user_id"],
        action="Downloaded Shared File",
        filename=file.filename
    )

    db.session.add(activity)

    file.download_count += 1
    file.last_download = datetime.utcnow()

    db.session.commit()

    # Remove one-time download authorization
    session.pop(
        f"secret_verified_{file_id}",
        None
    )

    return send_from_directory(
        DECRYPTED_FOLDER,
        os.path.basename(decrypted_path),
        as_attachment=True,
        download_name=file.filename
    )




# ---------------- DECRYPT ---------------- #

@app.route("/decrypt")
def decrypt():
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    filename = request.args.get("file")

    file = File.query.filter_by(
        encrypted_filename=filename,
        owner_id=session["user_id"]
    ).first()

    if file is None:
        return "File not found.", 404

    if not verify_file_integrity(
        file,
        session["user_id"]
    ):

        flash(
            "Integrity verification failed.",
            "danger"
        )

        return redirect(url_for("dashboard"))
        
    # Download encrypted AES key from B2
    key_path = os.path.join(
        ENCRYPTED_KEYS_FOLDER,
        f"decrypt_{file.id}.key.enc"
    )
    download_from_b2(
        file.aes_key_filename,
        key_path
    )
    with open(key_path, "rb") as key_file:
        encrypted_key = key_file.read()
        
    aes_key = decrypt_aes_key(encrypted_key)
    
    file.integrity_status = "Verified"
    db.session.commit()

    # Download encrypted file from B2
    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        f"decrypt_{file.id}.enc"
        )

    download_from_b2(
        file.encrypted_filename,
        encrypted_path
        )

    # Decrypt the downloaded encrypted file
    
    decrypted_path = decrypt_file(
        encrypted_path,
        aes_key
        )

    activity = Activity(
        user_id=session["user_id"],
        action="Decrypted",
        filename=file.filename
    )
    db.session.add(activity)
    db.session.commit()

    return send_from_directory(
        DECRYPTED_FOLDER,
        os.path.basename(decrypted_path),
        as_attachment=True,
        download_name=file.filename
    )


# ---------------- DELETE ---------------- #

@app.route("/delete/<int:file_id>")
def delete(file_id):
    if "user_id" not in session:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"]
    ).first()

    if file is None:
        return "File not found.", 404

    encrypted_path = os.path.join(ENCRYPTED_FOLDER, file.encrypted_filename)

    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    if hasattr(file, 'aes_key_filename') and file.aes_key_filename:
        key_file_path = os.path.join(ENCRYPTED_KEYS_FOLDER, file.aes_key_filename)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)

    log_file_access(
        session["user_id"],
        file.owner_id,
        file,
        "Delete"
    )

    activity = Activity(
        user_id=session["user_id"],
        action="Moved to Recycle Bin",
        filename=file.filename
    )
    db.session.add(activity)

    # Update storage usage
    user = User.query.get(session["user_id"])
    user.storage_used -= file.file_size
    if user.storage_used < 0:
        user.storage_used = 0

    # Move to Recycle Bin
    file.is_deleted = True
    file.deleted_at = datetime.utcnow()
    file.deleted_by = session["user_id"]

    db.session.commit()
    flash("File moved to Recycle Bin.", "success")
    return redirect(url_for("dashboard"))


# ---------------- EXPORT ACTIVITY LOG ---------------- #

@app.route("/export-activity")
def export_activity():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect("/login")

    activities = Activity.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        Activity.timestamp.desc()
    ).all()

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Action",
        "Filename",
        "Timestamp"
    ])

    for activity in activities:
        writer.writerow([
            activity.action,
            activity.filename,
            activity.timestamp
        ])

    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=activity_log.csv"
        }
    )


# ---------------- SHARE ROUTE ---------------- #

@app.route("/share/<int:file_id>", methods=["GET", "POST"])
def share_file(file_id):
    if "user_id" not in session:
        return redirect("/login")

    file = File.query.filter_by(
        id=file_id,
        owner_id=session["user_id"]
    ).first_or_404()

    if request.method == "POST":
        email = request.form["email"]
        share_password = request.form["share_password"]
        expiry = request.form.get("expiry")

        if len(share_password) < 6:
            flash(
                "Share password must be at least 6 characters long.",
                "danger"
            )
            return redirect(request.url)

        receiver = User.query.filter_by(
            email=email
        ).first()

        if receiver is None:
            flash("User not found.", "danger")
            return redirect(request.url)

        # Convert expiry string to datetime
        expires_at = None
        if expiry:
            expires_at = datetime.strptime(
                expiry,
                "%Y-%m-%dT%H:%M"
            )

        existing_share = SharedFile.query.filter_by(
            file_id=file.id,
            receiver_id=receiver.id
        ).first()

        if existing_share:
            flash(
                "This file has already been shared with this user.",
                "warning"
            )
            return redirect(request.url)

        key_path = os.path.join(
            ENCRYPTED_KEYS_FOLDER,
            file.aes_key_filename
        )
        with open(key_path, "rb") as key_file:
            encrypted_owner_key = key_file.read()
        aes_key = decrypt_aes_key(encrypted_owner_key)
        receiver_encrypted_key = encrypt_aes_key_with_public_key(
            aes_key,
            receiver.public_key
        )

        password_hash = generate_password_hash(share_password)

        # Generate one-time secret
        one_time_secret = generate_one_time_secret()

        # Store only the hash
        one_time_secret_hash = hash_one_time_secret(
            one_time_secret
        )

        # Encrypt the secret using receiver's public key
        encrypted_one_time_secret = encrypt_aes_key_with_public_key(
            one_time_secret.encode("utf-8"),
            receiver.public_key
        )
        encrypted_one_time_secret_b64 = base64.b64encode(
            encrypted_one_time_secret

            ).decode("utf-8")
        shared = SharedFile(
            file_id=file.id,
            sender_id=session["user_id"],
            receiver_id=receiver.id,
            expires_at=expires_at,
            is_active=True,
            share_password_hash=password_hash,
            one_time_secret_hash=one_time_secret_hash,
            one_time_secret_used=False
        )
        
        db.session.add(shared)

        shared_key = SharedKey(
            file_id=file.id,
            receiver_id=receiver.id,
            encrypted_aes_key=receiver_encrypted_key
        )
        db.session.add(shared_key)
        
        db.session.commit()

        log_file_access(
            session["user_id"],
            file.owner_id,
            file,
            "Share"
        )

        try:

            send_share_email(
                receiver.email,
                receiver.name,
                session["user_name"],
                file.filename,
                expires_at,
                encrypted_one_time_secret_b64
            )
        except Exception as e:

            print("Share Email Error:", e)

        activity = Activity(
            user_id=session["user_id"],
            action="Shared File",
            filename=file.filename
            )
        
        db.session.add(activity)
        db.session.commit()
        
        flash("File shared successfully.", "success")
        return redirect("/dashboard")

    return render_template(
        "share.html",
        file=file
    )


# ---------------- MANAGE SHARES ---------------- #

@app.route("/manage-shares")
def manage_shares():

    if "user_id" not in session:
        return redirect("/login")

    shares = (
        db.session.query(
            SharedFile,
            File,
            User
        )
        .join(File, SharedFile.file_id == File.id)
        .join(User, SharedFile.receiver_id == User.id)
        .filter(SharedFile.sender_id == session["user_id"])
        .all()
    )

    return render_template(
        "manage_shares.html",
        shares=shares
    )


# ---------------- REVOKE SHARE ---------------- #

@app.route("/revoke-share/<int:share_id>")
def revoke_share(share_id):

    if "user_id" not in session:
        return redirect("/login")

    share = SharedFile.query.get_or_404(share_id)

    if share.sender_id != session["user_id"]:

        flash("Access denied.", "danger")

        return redirect("/dashboard")

    shared_key = SharedKey.query.filter_by(

        file_id=share.file_id,

        receiver_id=share.receiver_id

    ).first()

    if shared_key:

        db.session.delete(shared_key)

    db.session.delete(share)

    activity = Activity(

        user_id=session["user_id"],

        action="Revoked Share",

        filename=File.query.get(share.file_id).filename

    )

    db.session.add(activity)

    db.session.commit()

    flash("Access revoked successfully.", "success")

    return redirect("/manage-shares")


# ---------------- SHARED FILES ---------------- #

@app.route("/shared-files")
def shared_files():
    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect("/login")

    shared_files = (
        db.session.query(SharedFile, File, User)
        .join(File, SharedFile.file_id == File.id)
        .join(User, SharedFile.sender_id == User.id)
        .filter(SharedFile.receiver_id == session["user_id"])
        .all()
    )

    return render_template(
        "shared_files.html",
        shared_files=shared_files,
        now=datetime.utcnow()
    )

# ---------------- ADMIN ACTIVITY LOGS ---------------- #

@app.route("/admin/activity-logs")
def admin_activity_logs():

    # Check login
    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    # Get current user
    admin = User.query.get(session["user_id"])

    # Check admin
    if admin is None or not admin.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    # Get search/filter values
    search = request.args.get("search", "").strip()
    action = request.args.get("action", "").strip()

    query = Activity.query

    # Search by action or filename
    if search:
        query = query.filter(
            or_(
                Activity.action.ilike(f"%{search}%"),
                Activity.filename.ilike(f"%{search}%")
            )
        )

    # Filter by action
    if action:
        query = query.filter(Activity.action == action)

    # Latest activities first
    activities = query.order_by(
        Activity.timestamp.desc()
    ).all()

    # Statistics
    total_activities = Activity.query.count()

    login_count = Activity.query.filter(
        Activity.action.ilike("%Login%")
    ).count()

    upload_count = Activity.query.filter(
        Activity.action.ilike("%Upload%")
    ).count()

    download_count = Activity.query.filter(
        Activity.action.ilike("%Download%")
    ).count()

    share_count = Activity.query.filter(
        Activity.action.ilike("%Share%")
    ).count()

    return render_template(
        "admin/activity_logs.html",
        activities=activities,
        total_activities=total_activities,
        login_count=login_count,
        upload_count=upload_count,
        download_count=download_count,
        share_count=share_count,
        search=search,
        selected_action=action
    )

# ---------------- ADMIN SECURITY REPORT ---------------- #

@app.route("/admin/security-report")
def security_report():

    if "user_id" not in session:
        return redirect("/login")

    if not session.get("is_admin"):
        flash("Access denied.", "danger")
        return redirect("/dashboard")

    total_users = User.query.count()
    total_files = File.query.count()
    shared_files = SharedFile.query.count()
    verified_files = File.query.filter_by(
        integrity_status="Verified"
    ).count()
    tampered_files = File.query.filter_by(
        integrity_status="Tampered"
    ).count()
    deleted_files = File.query.filter_by(
        is_deleted=True
    ).count()
    total_downloads = db.session.query(
        db.func.sum(File.download_count)
    ).scalar() or 0
    security_incidents = Activity.query.filter(
        Activity.action.like("%Security Alert%")
    ).count()

    pdf_path = os.path.join(
        BASE_DIR,
        "security_report.pdf"
    )

    doc = SimpleDocTemplate(pdf_path)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(
        Paragraph(
            "SecureVault Security Report",
            styles["Heading1"]
        )
    )

    data = [
        ["Metric", "Value"],
        ["Total Users", total_users],
        ["Total Files", total_files],
        ["Shared Files", shared_files],
        ["Verified Files", verified_files],
        ["Tampered Files", tampered_files],
        ["Deleted Files", deleted_files],
        ["Downloads", total_downloads],
        ["Security Alerts", security_incidents],
        ["Generated", datetime.utcnow().strftime("%d-%m-%Y %H:%M UTC")]
    ]

    table = Table(data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("TEXTCOLOR",(0,0),(-1,0),colors.whitesmoke),
        ("GRID",(0,0),(-1,-1),1,colors.black),
        ("BACKGROUND",(0,1),(-1,-1),colors.beige),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,0),10)
    ]))

    elements.append(table)
    doc.build(elements)

    return send_from_directory(
        BASE_DIR,
        "security_report.pdf",
        as_attachment=True
    )


# ---------------- ADMIN FILE ACCESS LOGS ---------------- #

@app.route("/admin/file-access")
def admin_file_access():

    if "user_id" not in session:
        return redirect("/login")

    if not session.get("is_admin"):
        return redirect("/dashboard")

    logs = FileAccessLog.query.order_by(
        FileAccessLog.access_time.desc()
    ).all()

    return render_template(
        "file_access_logs.html",
        logs=logs
    )


# ---------------- SECURITY ALERTS ---------------- #

@app.route("/admin/security-alerts")
def security_alerts():

    if not session.get("is_admin"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    query = SecurityAlert.query
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")

    if search:
        query = query.filter(
            or_(
                SecurityAlert.alert_type.ilike(f"%{search}%"),
                SecurityAlert.description.ilike(f"%{search}%")
            )
        )

    if severity:
        query = query.filter(SecurityAlert.severity == severity)

    if status:
        query = query.filter(SecurityAlert.status == status)

    alerts = query.order_by(SecurityAlert.created_at.desc()).all()

    total_alerts = len(alerts)
    open_alerts = sum(1 for a in alerts if a.status == "Open")
    resolved_alerts = sum(1 for a in alerts if a.status == "Resolved")
    high_alerts = sum(1 for a in alerts if a.severity == "High")

    return render_template(
        "admin/security_alerts.html",
        alerts=alerts,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        resolved_alerts=resolved_alerts,
        high_alerts=high_alerts,
    )


# ---------------- RESOLVE SECURITY ALERT ---------------- #

@app.route("/admin/security-alert/<int:alert_id>/resolve")
def resolve_security_alert(alert_id):

    if not session.get("is_admin"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    alert = SecurityAlert.query.get_or_404(alert_id)

    alert.status = "Resolved"
    alert.resolved_at = datetime.utcnow()

    db.session.commit()

    flash("Security alert marked as resolved.", "success")

    return redirect(url_for("security_alerts"))


# ---------------- DELETE SECURITY ALERT ---------------- #

@app.route("/admin/security-alert/<int:alert_id>/delete")
def delete_security_alert(alert_id):

    if not session.get("is_admin"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    alert = SecurityAlert.query.get_or_404(alert_id)

    db.session.delete(alert)
    db.session.commit()

    flash("Security alert deleted successfully.", "success")

    return redirect(url_for("security_alerts"))


# ---------------- SECURITY ALERT DETAILS ---------------- #

@app.route("/admin/security-alert/<int:alert_id>")
def security_alert_details(alert_id):

    if not session.get("is_admin"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    alert = SecurityAlert.query.get_or_404(alert_id)

    return render_template(
        "security_alert_details.html",
        alert=alert
    )


# ---------------- ADMIN DASHBOARD ---------------- #

@app.route("/admin")
def admin_dashboard():

    # Check login
    if "user_id" not in session:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    # Get current user
    current_user = User.query.get(session["user_id"])

    if current_user is None:
        session.clear()
        flash("User account not found. Please login again.", "danger")
        return redirect(url_for("login"))

    # Admin authorization
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------
    # BASIC STATISTICS
    # ------------------------------------------------

    total_users = User.query.count()

    total_files = File.query.count()

    total_activities = Activity.query.count()

    total_downloads = (
        db.session.query(
            db.func.coalesce(
                db.func.sum(File.download_count),
                0
            )
        ).scalar()
        or 0
    )

    total_storage_bytes = (
        db.session.query(
            db.func.coalesce(
                db.func.sum(File.file_size),
                0
            )
        ).scalar()
        or 0
    )

    # ------------------------------------------------
    # FORMAT TOTAL STORAGE
    # ------------------------------------------------

    if total_storage_bytes >= 1024 * 1024 * 1024:

        storage = f"{total_storage_bytes / (1024 * 1024 * 1024):.2f} GB"

    elif total_storage_bytes >= 1024 * 1024:

        storage = f"{total_storage_bytes / (1024 * 1024):.2f} MB"

    elif total_storage_bytes >= 1024:

        storage = f"{total_storage_bytes / 1024:.2f} KB"

    else:

        storage = f"{total_storage_bytes} B"

    # ------------------------------------------------
    # GET ALL USERS
    # ------------------------------------------------

    users = User.query.order_by(User.id.asc()).all()

    # ------------------------------------------------
    # FILE TYPE STATISTICS
    # ------------------------------------------------

    file_types = {}

    all_files = File.query.all()

    for file in all_files:

        file_type = file.file_type

        if not file_type:
            file_type = "Unknown"

        file_types[file_type] = (
            file_types.get(file_type, 0) + 1
        )

    # ------------------------------------------------
    # UPLOADS PER USER
    # ------------------------------------------------

    uploads_per_user = {}

    # ------------------------------------------------
    # STORAGE PER USER
    # ------------------------------------------------

    storage_per_user = {}

    # ------------------------------------------------
    # FILE COUNT PER USER
    # ------------------------------------------------

    user_files = {}

    for user in users:

        user_file_list = File.query.filter_by(
            owner_id=user.id
        ).all()

        # Number of files
        user_files[user.id] = len(user_file_list)

        # Upload count
        uploads_per_user[user.name] = len(user_file_list)

        # Storage
        user_storage = sum(
            (file.file_size or 0)
            for file in user_file_list
        )

        storage_per_user[user.name] = round(
            user_storage / 1024,
            2
        )

    # ------------------------------------------------
    # SECURITY ALERTS
    # ------------------------------------------------

    open_security_alerts = SecurityAlert.query.filter_by(
        status="Open"
    ).count()

    resolved_security_alerts = SecurityAlert.query.filter_by(
        status="Resolved"
    ).count()

    total_security_alerts = SecurityAlert.query.count()

    # ------------------------------------------------
    # RECENT ACTIVITIES
    # ------------------------------------------------

    recent_activities = Activity.query.order_by(
        Activity.timestamp.desc()
    ).limit(10).all()

    # ------------------------------------------------
    # RECENT FILES
    # ------------------------------------------------

    recent_files = File.query.order_by(
        File.upload_date.desc()
    ).limit(10).all()

    # ------------------------------------------------
    # RENDER ADMIN DASHBOARD
    # ------------------------------------------------

    return render_template(
        "admin_dashboard.html",

        # Current admin
        current_user=current_user,

        # Main statistics
        total_users=total_users,
        total_files=total_files,
        total_downloads=total_downloads,
        total_activities=total_activities,
        storage=storage,

        # Users
        users=users,
        user_files=user_files,

        # Charts/statistics
        file_types=file_types,
        uploads_per_user=uploads_per_user,
        storage_per_user=storage_per_user,

        # Security
        open_security_alerts=open_security_alerts,
        resolved_security_alerts=resolved_security_alerts,
        total_security_alerts=total_security_alerts,

        # Recent data
        recent_activities=recent_activities,
        recent_files=recent_files
    )

# ---------------- ADMIN USER DETAILS ---------------- #

@app.route("/admin/user/<int:user_id>")
def admin_user_details(user_id):

    # Admin must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get currently logged-in user
    admin = User.query.get(session["user_id"])

    # Make sure the current user is an admin
    if not admin or not admin.is_admin:
        abort(403)

    # Get selected user
    user = User.query.get_or_404(user_id)

    # Get all files owned by the user
    files = File.query.filter_by(
        owner_id=user.id
    ).all()

    # Get latest 10 activities
    activities = Activity.query.filter_by(
        user_id=user.id
    ).order_by(
        Activity.timestamp.desc()
    ).limit(10).all()

    # Calculate total storage
    storage_bytes = sum(
        file.file_size or 0
        for file in files
    )

    # Convert storage to readable format
    if storage_bytes >= 1024 * 1024:
        storage = f"{storage_bytes / (1024 * 1024):.2f} MB"

    elif storage_bytes >= 1024:
        storage = f"{storage_bytes / 1024:.2f} KB"

    else:
        storage = f"{storage_bytes} B"

    return render_template(
        "admin_user_details.html",
        user=user,
        files=files,
        activities=activities,
        storage=storage
    )

# ---------------- ADMIN UNLOCK USER ---------------- #

@app.route("/admin/unlock-user/<int:user_id>")
def admin_unlock_user(user_id):

    # Admin must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get current logged-in user
    admin = User.query.get(session["user_id"])

    # Verify admin privileges
    if not admin or not admin.is_admin:
        abort(403)

    # Get the user to unlock
    user = User.query.get_or_404(user_id)

    # Reset failed login attempts
    user.failed_attempts = 0

    # Remove account lock
    user.locked_until = None

    db.session.commit()

    flash(
        f"User '{user.name}' has been unlocked successfully.",
        "success"
    )

    return redirect(url_for("admin_dashboard"))


# ---------------- ADMIN DELETE USER ---------------- #

@app.route("/admin/delete-user/<int:user_id>")
def admin_delete_user(user_id):

    if "user_id" not in session:
        return redirect("/login")

    admin = User.query.get(session["user_id"])

    if not admin.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)

    # Don't allow deleting another admin
    if user.is_admin:
        flash("Admin account cannot be deleted.", "danger")
        return redirect(url_for("admin_dashboard"))

    # Delete user's files first
    File.query.filter_by(owner_id=user.id).delete()

    # Delete user's activities
    Activity.query.filter_by(user_id=user.id).delete()

    # Delete shared file references
    SharedFile.query.filter(
        (SharedFile.sender_id == user.id) |
        (SharedFile.receiver_id == user.id)
    ).delete(synchronize_session=False)

    activity = Activity(
    user_id=session["user_id"],
    action="Deleted User",
    filename=user.email
)
    db.session.add(activity)

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    flash("User deleted successfully.", "success")

    return redirect(url_for("admin_dashboard"))


# ---------------- ADMIN FILES ---------------- #

@app.route("/admin/files")
def admin_files():

    if "user_id" not in session:
        return redirect(url_for("login"))

    admin = User.query.get(session["user_id"])

    if not admin.is_admin:
        abort(403)

    files = File.query.order_by(File.upload_date.desc()).all()

    users = {user.id: user.name for user in User.query.all()}

    return render_template(
        "admin_files.html",
        files=files,
        users=users
    )


# ---------------- ADMIN DELETE FILE ---------------- #

@app.route("/admin/delete-file/<int:file_id>")
def admin_delete_file(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    admin = User.query.get(session["user_id"])

    if not admin.is_admin:
        abort(403)

    file = File.query.get_or_404(file_id)
    activity = Activity(
    user_id=session["user_id"],
    action="Admin Deleted File",
    filename=file.filename
)
    db.session.add(activity)

    # Delete encrypted file
    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        file.encrypted_filename
    )

    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    # Delete encrypted AES key
    key_path = os.path.join(
        ENCRYPTED_KEYS_FOLDER,
        file.aes_key_filename
    )

    if os.path.exists(key_path):
        os.remove(key_path)

    # Delete related share records
    SharedFile.query.filter_by(file_id=file.id).delete()

    # Log admin activity
    activity = Activity(
        user_id=session["user_id"],
        action="Admin Deleted File",
        filename=file.filename
    )

    db.session.add(activity)

    db.session.delete(file)
    db.session.commit()

    flash("File deleted successfully.", "success")

    return redirect(url_for("admin_files"))


# ---------------- ADMIN AUDIT LOG ---------------- #

@app.route("/admin/audit-log")
def admin_audit_log():

    if "user_id" not in session:
        return redirect("/login")

    if not session.get("is_admin"):
        abort(403)

    logs = (
        db.session.query(Activity, User)
        .join(User, Activity.user_id == User.id)
        .order_by(Activity.timestamp.desc())
        .all()
    )

    return render_template(
        "admin_audit_log.html",
        logs=logs
    )


# ---------------- TEST EMAIL ---------------- #

@app.route("/test-email")
def test_email():
    try:
        send_brevo_email(
            to_email="securevault.test@gmail.com",
            subject="SecureVault Test Email",
            body="This is a test email sent from SecureVault."
        )

        flash("Test email sent successfully.", "success")

    except Exception as e:
        print(e)
        flash(f"Failed to send email: {e}", "danger")

    return redirect(url_for("admin_dashboard"))

# ---------------- DATABASE ---------------- #

with app.app_context():
    db.create_all()


# ---------------- RUN APP ---------------- #

if __name__ == "__main__":
    app.run(debug=True)