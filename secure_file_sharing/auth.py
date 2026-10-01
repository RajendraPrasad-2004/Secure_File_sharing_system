"""
auth.py - Registration, login, session handling, CSRF and security logging.

Security notes
--------------
* Passwords are hashed with Werkzeug (salted, slow hash). Plaintext is never stored.
* After a successful login the user's RSA private key is decrypted (using the
  password) and kept ONLY in server memory, indexed by a random session token.
  It is never written to the cookie or to disk, and is wiped at logout/expiry.
* Repeated failed logins temporarily lock the account.
"""
import re
import secrets
import hmac
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import session, request, redirect, url_for, flash, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash

import crypto_utils as cu
from database import get_db

# session token -> (private_key_pem, expiry_timestamp). Server memory only.
UNLOCKED_KEYS = {}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Used to keep login timing similar when the user does not exist.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


# ------------------------------------------------------------------ logging
def log_event(user_id, action, status):
    """Write a row to security_logs (IP address taken from the request)."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO security_logs (user_id, action, ip_address, status) VALUES (?, ?, ?, ?)",
            (user_id, action, request.remote_addr, status),
        )
        db.commit()
    except Exception:  # logging must never break the request
        current_app.logger.exception("Failed to write security log")


# --------------------------------------------------------------------- CSRF
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_is_valid():
    sent = request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    return bool(sent) and bool(expected) and hmac.compare_digest(sent, expected)


# ------------------------------------------------------------- key registry
def _purge_expired_keys():
    now = time.time()
    for token in [t for t, (_, exp) in UNLOCKED_KEYS.items() if exp < now]:
        UNLOCKED_KEYS.pop(token, None)


def get_private_key():
    """Return the logged-in user's decrypted RSA private key (PEM bytes) or None."""
    entry = UNLOCKED_KEYS.get(session.get("token"))
    if not entry or entry[1] < time.time():
        return None
    return entry[0]


# ------------------------------------------------------------- registration
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one number."
    if len(password) > 128:
        return "Password is too long (max 128 characters)."
    return None


def register_user(username, email, password, confirm):
    """Return (True, None) or (False, error_message)."""
    username, email = username.strip(), email.strip().lower()
    if not USERNAME_RE.match(username):
        return False, "Username must be 3-30 characters: letters, numbers, underscore."
    if not EMAIL_RE.match(email) or len(email) > 254:
        return False, "Enter a valid email address."
    if password != confirm:
        return False, "Passwords do not match."
    err = validate_password(password)
    if err:
        return False, err

    db = get_db()
    exists = db.execute(
        "SELECT 1 FROM users WHERE lower(username) = lower(?) OR email = ?", (username, email)
    ).fetchone()
    if exists:
        log_event(None, f"REGISTER username={username}", "FAILURE")
        return False, "That username or email is already registered."

    public_pem, private_pem = cu.generate_rsa_keypair()
    enc_private = cu.protect_private_key(private_pem, password)
    cur = db.execute(
        "INSERT INTO users (username, email, password_hash, public_key, encrypted_private_key) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, email, generate_password_hash(password), public_pem.decode(), enc_private),
    )
    db.commit()
    log_event(cur.lastrowid, "REGISTER", "SUCCESS")
    return True, None


# -------------------------------------------------------------------- login
def authenticate(identifier, password):
    """
    Verify credentials. On success, starts a session and returns (user_row, None).
    On failure returns (None, error_message). Error text is deliberately generic.
    """
    cfg = current_app.config
    identifier = identifier.strip().lower()
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE lower(username) = ? OR email = ?", (identifier, identifier)
    ).fetchone()
    generic = "Invalid username/email or password."

    if user is None:
        check_password_hash(_DUMMY_HASH, password)
        log_event(None, f"LOGIN identifier={identifier[:40]}", "FAILURE")
        return None, generic

    now = datetime.now(timezone.utc)
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if locked_until > now:
            log_event(user["id"], "LOGIN (account locked)", "BLOCKED")
            return None, f"Account temporarily locked. Try again in {cfg['LOCKOUT_MINUTES']} minutes."

    if not check_password_hash(user["password_hash"], password):
        attempts = user["failed_attempts"] + 1
        locked = None
        if attempts >= cfg["MAX_FAILED_ATTEMPTS"]:
            locked = (now + timedelta(minutes=cfg["LOCKOUT_MINUTES"])).isoformat()
            attempts = 0
            log_event(user["id"], "ACCOUNT_LOCKED", "WARNING")
        db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                   (attempts, locked, user["id"]))
        db.commit()
        log_event(user["id"], "LOGIN", "FAILURE")
        return None, generic

    # Success: unlock the private key with the password
    try:
        private_pem = cu.unlock_private_key(user["encrypted_private_key"], password)
    except cu.DecryptionError:
        log_event(user["id"], "LOGIN (private key unlock failed)", "FAILURE")
        return None, "Your key store could not be unlocked."

    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    db.commit()

    _purge_expired_keys()
    session.clear()                                   # prevents session fixation
    token = secrets.token_urlsafe(32)
    lifetime = cfg["PERMANENT_SESSION_LIFETIME_MINUTES"] * 60
    UNLOCKED_KEYS[token] = (private_pem, time.time() + lifetime)
    session.permanent = True
    session["user_id"] = user["id"]
    session["token"] = token
    log_event(user["id"], "LOGIN", "SUCCESS")
    return user, None


def logout_user():
    uid = session.get("user_id")
    UNLOCKED_KEYS.pop(session.get("token"), None)     # wipe private key from memory
    if uid:
        log_event(uid, "LOGOUT", "SUCCESS")
    session.clear()


# --------------------------------------------------------------- decorators
def load_current_user():
    """Populate g.user from the session (called before each request)."""
    g.user = None
    uid = session.get("user_id")
    if uid and get_private_key() is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            UNLOCKED_KEYS.pop(session.get("token"), None)
            session.clear()
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped
