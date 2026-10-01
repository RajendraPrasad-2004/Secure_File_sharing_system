"""
config.py - Central configuration.

No cryptographic secret is hardcoded. The Flask session-signing key is read
from the SFS_SECRET_KEY environment variable, or generated randomly on first
run and stored in keys/secret_key.bin (excluded from version control).
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database", "database.db")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted_files")
KEYS_DIR = os.path.join(BASE_DIR, "keys")

MAX_FILE_SIZE = 10 * 1024 * 1024            # 10 MB per upload
MAX_CONTENT_LENGTH = MAX_FILE_SIZE + 64 * 1024  # request limit (file + form overhead)
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "csv", "zip", "md",
}

# Failed-login handling
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# Session cookie hardening
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = False   # set True when serving over HTTPS
PERMANENT_SESSION_LIFETIME_MINUTES = 30


def load_secret_key():
    """Return the session signing key (env var > persisted random key)."""
    env_key = os.environ.get("SFS_SECRET_KEY")
    if env_key:
        return env_key.encode()
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, "secret_key.bin")
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(os.urandom(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path, "rb") as fh:
        return fh.read()
