# Secure File Sharing System Using Hybrid Cryptography

**Course:** Information and Network Security  
**Stack:** Python Flask, HTML/CSS/JavaScript, SQLite (`sqlite3`), `cryptography` (AES-256-GCM, RSA-2048-OAEP), Werkzeug password hashing

Registered users can upload, store, download and share files. File contents are encrypted with **AES-256-GCM**; the AES key is protected with **RSA-2048 (OAEP, SHA-256)**. The server never stores a plaintext file.

---

## 1. Project structure

```
secure_file_sharing/
├── app.py            Flask app factory, routes, security headers, error pages
├── config.py         Settings (limits, allowed types); secret key loaded, never hardcoded
├── database.py       SQLite connection + schema (users, files, file_shares, security_logs)
├── crypto_utils.py   ALL cryptography (AES-GCM, RSA-OAEP, scrypt key wrapping)
├── auth.py           Registration, login, lockout, sessions, CSRF, security logging
├── file_manager.py   Encrypted upload/download, sharing, authorization checks
├── requirements.txt
├── database/         database.db is created here on first run
├── encrypted_files/  Ciphertext only (random names, .enc)
├── keys/             secret_key.bin (random session-signing key, created on first run)
├── templates/        login, register, dashboard, upload, files, shared_files, share, logs (+ base, error)
├── static/css/style.css, static/js/script.js
└── tests/test_app.py Automated tests (19)
```

---

## 2. Installation (Windows)

Requires Python 3.9 or newer.

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in your browser. The database and the session key are created automatically on first start.
Stop the server with `Ctrl+C`. (On Linux/macOS use `source venv/bin/activate`.)

Run the tests:

```bash
python -m unittest -v tests.test_app
```

---

## 3. Cryptographic design

### Why hybrid encryption?

| | AES-256-GCM (symmetric) | RSA-2048 (asymmetric) |
|---|---|---|
| Speed | Very fast, any file size | Slow |
| Data limit | None practical | ~190 bytes with OAEP-SHA256 |
| Key distribution | Hard: both sides need the same secret | Easy: public key can be shared openly |
| Integrity | Yes (GCM authentication tag) | No |

So **AES encrypts the file** (fast, authenticated) and **RSA encrypts only the 32-byte AES key** (solves key distribution). Every file gets a fresh random AES key and a fresh random 12-byte nonce.

### Upload flow

```
file --validate--> AES-256-GCM(random key, random nonce) --> ciphertext+tag --> encrypted_files/<random>.enc
random AES key --> RSA-OAEP(owner's public key) --> files.encrypted_aes_key (SQLite)
```

### Download flow

```
check login -> check owner/share row (SQL, using session user id)
-> RSA-OAEP decrypt wrapped key with the user's private key
-> AES-GCM decrypt + verify tag -> stream original file (memory only)
```

### Sharing (no re-encryption of the file)

The owner's private key unwraps the AES key, which is then wrapped again with the **recipient's public key** and stored in `file_shares.encrypted_aes_key`. Each user therefore unwraps the key with their own private key. Revoking a share deletes that row.

### Integrity

GCM appends a 16-byte tag. Any modification of the ciphertext (even one bit) makes decryption raise `DecryptionError`; the user sees an integrity error and **no data is returned**. The storage filename is also bound to the ciphertext as associated data (AAD), so ciphertext files cannot be swapped between records.

---

## 4. Private key protection and its limits

At registration an RSA-2048 key pair is generated. The private key is encrypted with **AES-256-GCM using a key derived from the user's password with scrypt** (random 16-byte salt) and stored as `base64(salt || nonce || ciphertext)`. At login the password unlocks it; the decrypted key lives **only in server memory**, tied to a random session token, and is deleted at logout or session expiry.

**Limitations (demonstration-level):**

* The server briefly sees the password and the unlocked private key, so a compromised server process exposes active users' keys. True end-to-end encryption would do the crypto in the browser.
* Changing a password requires re-wrapping the private key (not implemented). **A forgotten password means the files cannot be recovered**; there is no key escrow or recovery.
* A weak password means a weak key wrapper, since an attacker with the database can brute-force it offline (scrypt makes this slower but not impossible).
* Unlocked keys are kept in a Python dictionary, so they are lost when the server restarts (users must log in again) and the app supports one server process only.
* No forward secrecy or key rotation for user key pairs.

**Production approach:** keep keys in a dedicated key-management service or HSM (AWS KMS, Azure Key Vault, HashiCorp Vault). Use envelope encryption with KMS-held master keys, per-user key policies, audited key access, automatic rotation, and recovery procedures.

---

## 5. Security features

| Requirement | Implementation |
|---|---|
| Password security | Werkzeug `generate_password_hash` / `check_password_hash` (salted); policy: 8+ chars, letter + number |
| Authentication | Session cookie (HttpOnly, SameSite=Lax, 30 min lifetime); session reset at login prevents fixation |
| Failed login handling | Generic error message; 5 failures lock the account for 5 minutes; dummy hash check keeps timing similar for unknown users |
| Authorization | Owner/share check in SQL with the session user id; unauthorized and missing files both return 404 so IDs cannot be probed |
| Path traversal | `secure_filename` on uploads; files stored under random hex names; `realpath` + `commonpath` guard |
| File validation | Extension whitelist, 10 MB limit, empty-file check, request size cap |
| CSRF | Per-session token on every POST form, compared with `hmac.compare_digest` |
| HTTP headers | CSP (no inline script/style), X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, `Cache-Control: no-store` |
| SQL injection | Parameterised queries only |
| XSS | Jinja2 autoescaping + strict CSP |
| Logging | `security_logs`: user, action, IP, timestamp, status (SUCCESS/FAILURE/DENIED/BLOCKED/WARNING) |
| No hardcoded secrets | Session key from `SFS_SECRET_KEY` or random `keys/secret_key.bin` |
| No custom crypto | Only `cryptography` library primitives |

For HTTPS deployment set `SESSION_COOKIE_SECURE = True` in `config.py` and run behind a TLS-terminating server (not Flask's development server).

---

## 6. Database

The schema is in `database.py` (`SCHEMA`) and is applied by `init_db()` at startup. Beyond the required columns, three were added for correctness: `users.failed_attempts` / `locked_until` (lockout), `files.file_size`, and `file_shares.encrypted_aes_key` (the AES key wrapped for each recipient, which is what makes sharing possible with hybrid encryption).

---

## 7. Test cases and expected results

Automated: `python -m unittest -v tests.test_app` (19 tests, all passing).

| # | Test | Steps | Expected result |
|---|---|---|---|
| 1 | Registration | Submit valid form | "Account created"; DB holds a password hash (not the password), a public key, and an encrypted private key (no "PRIVATE KEY" text). Mismatched/weak/duplicate input is rejected. |
| 2 | Login | Log in with username, then with email | Dashboard shows "Welcome back, <user>". |
| 3 | Wrong password | Log in with a bad password | "Invalid username/email or password"; dashboard still redirects to login. After 5 failures the account is locked even for the correct password. |
| 4 | File upload | Upload `report.txt` | "encrypted and stored"; file appears in My Files. Oversized, empty and disallowed types are rejected. |
| 5 | File encryption | Inspect `encrypted_files/*.enc` and the DB | Ciphertext does not contain the plaintext; size = original + 16-byte tag; nonce is 12 bytes; wrapped key is 256 bytes (RSA-2048). |
| 6 | File download | Click Download as owner | Browser receives the file; content is identical to the original. |
| 7 | File decryption | Same as 6 / crypto unit tests | AES-GCM round trip works; wrong key, wrong AAD, or modified ciphertext raises `DecryptionError`. |
| 8 | File sharing | Alice shares with Bob | "Shared with bob"; the file appears in Bob's Shared Files; Bob downloads identical content; the wrapped keys for Alice and Bob differ. |
| 9 | Unauthorized access | Carol opens `/download/1`, `/share/1`; Bob tries to re-share; anonymous user | 404 for Carol and Bob; redirect to login for anonymous; DENIED rows appear in the security log. |
| 10 | Modified encrypted file | Flip one bit in the `.enc` file, then download | "Integrity check failed" message; no file data returned; FAILURE logged. |
| 11 | Logout | Click Log out, then open `/dashboard` | Redirect to login; the private key is removed from server memory. |
| 12 | Security logging | Perform register, login, upload, download, failed login, logout | A row for each action with IP address, timestamp and status in the Security Logs page. |

Extra tests cover CSRF rejection (400 without a token), path-traversal filenames (`../../evil.txt` becomes `evil.txt`), and share revocation.

---

## 8. Demonstration flow

1. **Start** the app and open http://127.0.0.1:5000.
2. **Register** two users, `alice` and `bob` (use two different browsers or one normal and one private window, since sessions are cookie-based). Show the weak-password rejection and the strength meter.
3. **Log in as alice** and point out the dashboard (counts, recent uploads, security activity).
4. **Upload** a text file containing a recognisable sentence. Explain the five steps shown on the page.
5. **Prove encryption:** open `encrypted_files/` and open the `.enc` file in an editor (unreadable). In an SQLite viewer show `encrypted_aes_key` and `nonce`. Search the folder for the sentence: not found.
6. **Download** the file from My Files; it opens with the original content (AES-GCM decrypted after RSA unwrapped the key).
7. **Share** the file with `bob` from the Share page.
8. **Log in as bob** in the other browser: the file is under Shared with me; download it successfully.
9. **Authorization attack:** register `carol` and, while logged in as her, browse to `/download/1`. Result: 404 "Not found", and the attempt appears as DENIED in carol's Security Logs.
10. **Integrity attack:** stop the server or just edit one byte of the `.enc` file, then download as alice. Result: "Integrity check failed", nothing returned.
11. **Revoke** bob's access from the Share page; bob's download now returns 404.
12. **Security Logs** page: walk through the recorded events, then **log out**, and show that the dashboard is no longer reachable.
13. Run `python -m unittest -v tests.test_app` to show all tests passing.

---

## 9. Known limitations

* Development server and a single process; use Gunicorn/Waitress plus HTTPS for real deployment.
* Whole files are encrypted in memory (limited to 10 MB); large files would need chunked/streaming encryption.
* No password reset, email verification, or MFA.
* The owner must be logged in to share (their private key is needed to unwrap the AES key). Recipients can download but not re-share.
