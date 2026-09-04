from database import db
from datetime import datetime, timedelta

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(100), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)
    
    failed_attempts = db.Column(db.Integer, default=0)

    locked_until = db.Column(db.DateTime)

    is_admin = db.Column(
        db.Boolean,
        default=False
    )

    email_verified = db.Column(
        db.Boolean,
        default=False
    )

    verification_token = db.Column(
        db.String(150),
        nullable=True
    )

    # ---------------- STORAGE ---------------- #
    storage_limit = db.Column(
        db.BigInteger,
        default=1073741824      # 1 GB
    )
    storage_used = db.Column(
        db.BigInteger,
        default=0
    )
    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    # ---------------- TWO FACTOR AUTH ---------------- #
    otp = db.Column(
        db.String(6),
        nullable=True
    )

    otp_created_at = db.Column(
        db.DateTime,
        nullable=True
    )

    two_factor_enabled = db.Column(
        db.Boolean,
        default=True
    )
# ---------------- RSA KEYS ---------------- #
    public_key = db.Column(
        db.Text,
        nullable=True
    )
    private_key = db.Column(
        db.Text,
        nullable=True
    )
    profile_picture = db.Column(
        db.String(255),
        default="default.png"
    )

class File(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(db.String(200), nullable=False)

    encrypted_filename = db.Column(db.String(200), nullable=False)

    aes_key_filename = db.Column(db.String(200), nullable=False)
    
    file_hash = db.Column(
        db.String(64),
        nullable=False
    )

    # ---------------- DIGITAL SIGNATURE ---------------- #
    signature = db.Column(
        db.Text,
        nullable=True
    )

    signature_algorithm = db.Column(
        db.String(30),
        default="RSA-2048"
    )

    signature_verified = db.Column(
        db.Boolean,
        default=True
    )

    owner_id = db.Column(db.Integer, nullable=False)

    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    file_size = db.Column(db.Integer)

    file_type = db.Column(db.String(20))

    download_count = db.Column(db.Integer, default=0)

    last_download = db.Column(db.DateTime)

    encryption_algorithm = db.Column(
        db.String(30),
        default="AES-256 + RSA-2048"
    )

    integrity_status = db.Column(
        db.String(20),
        default="Verified"
    )

    # Recycle Bin fields
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, nullable=True)

class FileVersion(db.Model):
    __tablename__ = "file_version"

    id = db.Column(db.Integer, primary_key=True)

    # Parent file
    file_id = db.Column(
        db.Integer,
        db.ForeignKey("file.id"),
        nullable=False
    )

    # Version number
    version_number = db.Column(
        db.Integer,
        nullable=False
    )

    # Original filename
    filename = db.Column(
        db.String(255),
        nullable=False
    )

    # Encrypted filename stored on disk
    encrypted_filename = db.Column(
        db.String(255),
        nullable=False
    )

    # RSA-encrypted AES key
    encrypted_key = db.Column(
        db.Text,
        nullable=False
    )

    # SHA-256 hash
    sha256_hash = db.Column(
        db.String(64),
        nullable=False
    )

    # Size
    file_size = db.Column(
        db.BigInteger,
        nullable=False
    )

    # Upload time
    upload_date = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    # Relationship to File
    file = db.relationship(
        "File",
        backref="versions"
    )

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, nullable=False)

    action = db.Column(db.String(100), nullable=False)

    filename = db.Column(db.String(200))

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

class FileAccessLog(db.Model):

    __tablename__ = "file_access_log"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        nullable=False
    )

    owner_id = db.Column(
        db.Integer,
        nullable=False
    )

    file_id = db.Column(
        db.Integer,
        nullable=False
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    action = db.Column(
        db.String(50),
        nullable=False
    )

    ip_address = db.Column(
        db.String(50),
        nullable=False
    )

    access_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

class SharedFile(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("file.id"),
        nullable=False
    )

    sender_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    receiver_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    shared_date = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=True
    )

    is_active = db.Column(
        db.Boolean,
        default=True
    )
    download_limit = db.Column(
    db.Integer,
    default=0
)

    download_count = db.Column(
    db.Integer,
    default=0
)

    # NEW
    share_password_hash = db.Column(
        db.String(255),
        nullable=True
    )

    one_time_secret_hash = db.Column(
        db.String(255),
        nullable=True
    )

    one_time_secret_used = db.Column(
        db.Boolean,
        default=False
    )

    one_time_secret_expires_at = db.Column(
        db.DateTime,
        nullable=True
    )

class SharedKey(db.Model):
    __tablename__ = "shared_keys"

    id = db.Column(db.Integer, primary_key=True)

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("file.id"),
        nullable=False
    )

    receiver_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    encrypted_aes_key = db.Column(
        db.LargeBinary,
        nullable=False
    )

    shared_on = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ---------------- PASSWORD RESET ---------------- #
class PasswordReset(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    token = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    used = db.Column(
        db.Boolean,
        default=False
    )

    user = db.relationship(
        "User",
        backref="password_resets"
    )

    login_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ---------------- LOGIN HISTORY ---------------- #
class LoginHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    login_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    logout_time = db.Column(
        db.DateTime,
        nullable=True
    )

    ip_address = db.Column(
        db.String(50),
        nullable=False
    )

    browser = db.Column(
        db.String(100),
        nullable=False
    )

    operating_system = db.Column(
        db.String(100),
        nullable=False
    )

    device = db.Column(
        db.String(100),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        default="Success"
    )


# ---------------- SECURITY ALERTS ---------------- #
class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("file.id"),
        nullable=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )

    alert_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)

    status = db.Column(
        db.String(20),
        default="Open"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    resolved_at = db.Column(
        db.DateTime,
        nullable=True
    )

    file = db.relationship("File")
    user = db.relationship("User")