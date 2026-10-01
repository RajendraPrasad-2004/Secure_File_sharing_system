"""
file_manager.py - Encrypted upload, download, sharing and deletion.

Authorization rule: a file may be accessed only by its owner, or by a user
that appears in file_shares for that file. The check is done in SQL using the
logged-in user's id (never a value supplied by the client), so editing a URL
or file id cannot grant access to someone else's data.
"""
import os
import secrets

from werkzeug.utils import secure_filename
from flask import current_app

import crypto_utils as cu
from database import get_db


class AccessDenied(Exception):
    """User is not the owner and has no share for this file."""


class FileMissing(Exception):
    """Database row exists but the encrypted file is gone from disk."""


def _ext_allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


def _storage_path(encrypted_filename):
    """Resolve a stored filename to a path, refusing anything outside ENCRYPTED_DIR."""
    base = os.path.realpath(current_app.config["ENCRYPTED_DIR"])
    path = os.path.realpath(os.path.join(base, encrypted_filename))
    if os.path.commonpath([base, path]) != base:       # path traversal guard
        raise AccessDenied("Invalid storage path")
    return path


# ------------------------------------------------------------------- upload
def upload_file(user, file_storage):
    """
    Validate -> AES-256-GCM encrypt -> wrap AES key with owner's RSA public key
    -> store ciphertext + metadata. Returns (ok, message, file_id).
    The plaintext only ever exists in memory.
    """
    if file_storage is None or not file_storage.filename:
        return False, "Choose a file to upload.", None
    original = secure_filename(file_storage.filename)       # strips ../ and odd characters
    if not original or not _ext_allowed(original):
        return False, "File type not allowed.", None

    max_size = current_app.config["MAX_FILE_SIZE"]
    data = file_storage.read(max_size + 1)
    if len(data) == 0:
        return False, "The file is empty.", None
    if len(data) > max_size:
        return False, f"File is larger than {max_size // (1024 * 1024)} MB.", None

    aes_key = cu.generate_aes_key()                          # fresh key per file
    encrypted_name = secrets.token_hex(16) + ".enc"          # random on-disk name
    nonce, ciphertext = cu.aes_encrypt(data, aes_key, aad=encrypted_name.encode())
    wrapped_key = cu.rsa_encrypt_key(user["public_key"].encode(), aes_key)

    path = _storage_path(encrypted_name)
    with open(path, "wb") as fh:
        fh.write(ciphertext)
    try:
        db = get_db()
        cur = db.execute(
            "INSERT INTO files (owner_id, original_filename, encrypted_filename, encrypted_aes_key, nonce, file_size) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user["id"], original, encrypted_name, cu.b64e(wrapped_key), cu.b64e(nonce), len(data)),
        )
        db.commit()
    except Exception:
        os.remove(path)                                      # never leave orphan ciphertext
        raise
    return True, f"'{original}' was encrypted and stored.", cur.lastrowid


# --------------------------------------------------------------- authorization
def get_access(file_id, user_id):
    """
    Return (file_row, wrapped_key_b64, role) if user_id may access file_id,
    otherwise None. role is 'owner' or 'shared'.
    """
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ? AND owner_id = ?", (file_id, user_id)).fetchone()
    if row:
        return row, row["encrypted_aes_key"], "owner"
    row = db.execute(
        "SELECT f.*, s.encrypted_aes_key AS shared_key FROM files f "
        "JOIN file_shares s ON s.file_id = f.id "
        "WHERE f.id = ? AND s.shared_with_user_id = ?", (file_id, user_id)).fetchone()
    if row:
        return row, row["shared_key"], "shared"
    return None


# ----------------------------------------------------------------- download
def decrypt_file_for_user(file_id, user_id, private_pem):
    """
    Authorize -> unwrap AES key with user's private key -> AES-GCM decrypt
    (verifying the tag). Returns (original_filename, plaintext_bytes).
    Raises AccessDenied, FileMissing or cu.DecryptionError.
    """
    access = get_access(file_id, user_id)
    if access is None:
        raise AccessDenied("No access to this file")
    row, wrapped_key_b64, _role = access

    aes_key = cu.rsa_decrypt_key(private_pem, cu.b64d(wrapped_key_b64))
    path = _storage_path(row["encrypted_filename"])
    if not os.path.isfile(path):
        raise FileMissing("Encrypted file not found on disk")
    with open(path, "rb") as fh:
        ciphertext = fh.read()
    plaintext = cu.aes_decrypt(ciphertext, aes_key, cu.b64d(row["nonce"]),
                               aad=row["encrypted_filename"].encode())
    return row["original_filename"], plaintext


# ------------------------------------------------------------------ sharing
def share_file(file_id, owner, recipient_username, owner_private_pem):
    """
    Owner shares a file with another user. The AES key is decrypted with the
    owner's private key and re-encrypted with the RECIPIENT's public key; the
    file itself is NOT re-encrypted. Returns (ok, message).
    """
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ? AND owner_id = ?", (file_id, owner["id"])).fetchone()
    if row is None:
        raise AccessDenied("Only the owner can share a file")
    recipient = db.execute("SELECT * FROM users WHERE lower(username) = lower(?)",
                           (recipient_username.strip(),)).fetchone()
    if recipient is None:
        return False, "No registered user with that username."
    if recipient["id"] == owner["id"]:
        return False, "You already own this file."
    if db.execute("SELECT 1 FROM file_shares WHERE file_id = ? AND shared_with_user_id = ?",
                  (file_id, recipient["id"])).fetchone():
        return False, f"Already shared with {recipient['username']}."

    aes_key = cu.rsa_decrypt_key(owner_private_pem, cu.b64d(row["encrypted_aes_key"]))
    wrapped_for_recipient = cu.rsa_encrypt_key(recipient["public_key"].encode(), aes_key)
    db.execute(
        "INSERT INTO file_shares (file_id, owner_id, shared_with_user_id, encrypted_aes_key) VALUES (?, ?, ?, ?)",
        (file_id, owner["id"], recipient["id"], cu.b64e(wrapped_for_recipient)))
    db.commit()
    return True, f"Shared with {recipient['username']}."


def revoke_share(share_id, owner_id):
    db = get_db()
    cur = db.execute("DELETE FROM file_shares WHERE id = ? AND owner_id = ?", (share_id, owner_id))
    db.commit()
    return cur.rowcount > 0


def delete_file(file_id, owner_id):
    """Delete ciphertext, wrapped keys (cascade) and metadata. Owner only."""
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id)).fetchone()
    if row is None:
        raise AccessDenied("Only the owner can delete a file")
    try:
        os.remove(_storage_path(row["encrypted_filename"]))
    except FileNotFoundError:
        pass
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    return row["original_filename"]


# -------------------------------------------------------------------- lists
def list_my_files(user_id):
    return get_db().execute(
        "SELECT f.*, (SELECT COUNT(*) FROM file_shares s WHERE s.file_id = f.id) AS share_count "
        "FROM files f WHERE f.owner_id = ? ORDER BY f.created_at DESC, f.id DESC", (user_id,)).fetchall()


def list_shared_with_me(user_id):
    return get_db().execute(
        "SELECT f.id, f.original_filename, f.file_size, s.created_at AS shared_at, u.username AS owner_name "
        "FROM file_shares s JOIN files f ON f.id = s.file_id JOIN users u ON u.id = f.owner_id "
        "WHERE s.shared_with_user_id = ? ORDER BY s.created_at DESC, s.id DESC", (user_id,)).fetchall()


def list_recipients(file_id, owner_id):
    return get_db().execute(
        "SELECT s.id AS share_id, u.username, s.created_at FROM file_shares s "
        "JOIN users u ON u.id = s.shared_with_user_id WHERE s.file_id = ? AND s.owner_id = ? "
        "ORDER BY s.created_at", (file_id, owner_id)).fetchall()


def dashboard_stats(user_id):
    db = get_db()
    one = lambda sql: db.execute(sql, (user_id,)).fetchone()[0]
    return {
        "total_files": one("SELECT COUNT(*) FROM files WHERE owner_id = ?"),
        "shared_with_me": one("SELECT COUNT(*) FROM file_shares WHERE shared_with_user_id = ?"),
        "shared_by_me": one("SELECT COUNT(DISTINCT file_id) FROM file_shares WHERE owner_id = ?"),
        "security_events": one("SELECT COUNT(*) FROM security_logs WHERE user_id = ?"),
        "recent_uploads": db.execute(
            "SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC, id DESC LIMIT 5", (user_id,)).fetchall(),
        "recent_events": db.execute(
            "SELECT * FROM security_logs WHERE user_id = ? ORDER BY id DESC LIMIT 5", (user_id,)).fetchall(),
    }
