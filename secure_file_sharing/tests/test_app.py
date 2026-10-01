"""
Automated tests. Run from the project root:   python -m unittest -v tests.test_app
Each test uses a throw-away temporary database and encrypted-file folder.
"""
import io
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth
import crypto_utils as cu
from app import create_app

PASSWORD = "Str0ngPass1"
CONTENT = b"TOP SECRET quarterly report - do not leak\n" * 50


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "test.db")
        self.enc_dir = os.path.join(self.tmp, "enc")
        self.app = create_app({"TESTING": True, "DATABASE": self.db_path, "ENCRYPTED_DIR": self.enc_dir,
                               "SECRET_KEY": b"test-only-key"})
        auth.UNLOCKED_KEYS.clear()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers
    def new_client(self):
        return self.app.test_client()

    @staticmethod
    def token(client, path="/login"):
        html = client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def register(self, client, username, password=PASSWORD, confirm=None):
        return client.post("/register", data={
            "csrf_token": self.token(client, "/register"), "username": username,
            "email": f"{username}@example.com", "password": password,
            "confirm_password": password if confirm is None else confirm}, follow_redirects=True)

    def login(self, client, identifier, password=PASSWORD):
        return client.post("/login", data={"csrf_token": self.token(client), "identifier": identifier,
                                           "password": password}, follow_redirects=True)

    def user_client(self, username):
        c = self.new_client()
        self.register(c, username)
        self.login(c, username)
        return c

    def upload(self, client, name="report.txt", data=CONTENT):
        return client.post("/upload", data={"csrf_token": self.token(client, "/upload"),
                                            "file": (io.BytesIO(data), name)},
                           content_type="multipart/form-data", follow_redirects=True)

    def share(self, client, file_id, username):
        return client.post(f"/share/{file_id}", data={"csrf_token": self.token(client, f"/share/{file_id}"),
                                                      "username": username}, follow_redirects=True)

    def query(self, sql, args=()):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, args).fetchall()
        conn.close()
        return rows

    @staticmethod
    def read_bytes(path):
        with open(path, "rb") as fh:
            return fh.read()

    @staticmethod
    def write_bytes(path, data):
        with open(path, "wb") as fh:
            fh.write(data)

    def enc_files(self):
        return [os.path.join(self.enc_dir, f) for f in os.listdir(self.enc_dir)]


class TestAuthentication(Base):
    def test_01_registration(self):
        c = self.new_client()
        r = self.register(c, "alice")
        self.assertIn(b"Account created", r.data)
        row = self.query("SELECT * FROM users WHERE username='alice'")[0]
        self.assertNotIn(PASSWORD, row["password_hash"])                 # hashed, not plaintext
        self.assertTrue(row["password_hash"].startswith(("scrypt:", "pbkdf2:")))
        self.assertIn("BEGIN PUBLIC KEY", row["public_key"])
        self.assertNotIn("PRIVATE KEY", row["encrypted_private_key"])    # private key not stored in clear

    def test_01b_registration_validation(self):
        c = self.new_client()
        self.assertIn(b"do not match", self.register(c, "bob", confirm="Different1").data)
        self.assertIn(b"at least 8", self.register(c, "bob", password="a1").data)
        self.register(c, "carol")
        self.assertIn(b"already registered", self.register(c, "carol").data)

    def test_02_login_success(self):
        c = self.new_client()
        self.register(c, "alice")
        r = self.login(c, "alice")
        self.assertIn(b"Welcome back, alice", r.data)

    def test_02b_login_with_email(self):
        c = self.new_client()
        self.register(c, "alice")
        c2 = self.new_client()
        self.assertIn(b"Welcome back, alice", self.login(c2, "alice@example.com").data)

    def test_03_wrong_password_and_lockout(self):
        c = self.new_client()
        self.register(c, "alice")
        r = self.login(c, "alice", "WrongPass9")
        self.assertIn(b"Invalid username/email or password", r.data)
        self.assertEqual(c.get("/dashboard").status_code, 302)          # still not logged in
        for _ in range(5):
            self.login(c, "alice", "WrongPass9")
        r = self.login(c, "alice", PASSWORD)                             # correct password, but locked
        self.assertIn(b"temporarily locked", r.data)

    def test_03b_csrf_required(self):
        c = self.new_client()
        c.get("/login")
        r = c.post("/login", data={"identifier": "a", "password": "b"})
        self.assertEqual(r.status_code, 400)

    def test_11_logout(self):
        c = self.user_client("alice")
        self.assertEqual(c.get("/dashboard").status_code, 200)
        c.post("/logout", data={"csrf_token": self.token(c, "/dashboard")})
        self.assertEqual(c.get("/dashboard").status_code, 302)          # redirected to login
        self.assertEqual(len(auth.UNLOCKED_KEYS), 0)                     # private key wiped from memory


class TestFiles(Base):
    def test_04_05_upload_and_encryption(self):
        c = self.user_client("alice")
        r = self.upload(c)
        self.assertIn(b"encrypted and stored", r.data)
        files = self.enc_files()
        self.assertEqual(len(files), 1)
        stored = self.read_bytes(files[0])
        self.assertNotIn(b"TOP SECRET", stored)                          # ciphertext, not plaintext
        self.assertEqual(len(stored), len(CONTENT) + 16)                 # + 16-byte GCM tag
        row = self.query("SELECT * FROM files")[0]
        self.assertEqual(len(cu.b64d(row["nonce"])), 12)                 # 12-byte nonce
        self.assertEqual(len(cu.b64d(row["encrypted_aes_key"])), 256)    # RSA-2048 block
        # no plaintext copy anywhere under the temp tree
        for root, _, names in os.walk(self.tmp):
            for n in names:
                if n != "test.db":
                    self.assertNotIn(b"TOP SECRET", self.read_bytes(os.path.join(root, n)))

    def test_06_07_download_decrypts(self):
        c = self.user_client("alice")
        self.upload(c)
        r = c.get("/download/1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, CONTENT)
        self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_upload_validation(self):
        c = self.user_client("alice")
        self.assertIn(b"not allowed", self.upload(c, "virus.exe").data)
        self.assertIn(b"empty", self.upload(c, "empty.txt", b"").data)
        self.assertIn(b"larger than", self.upload(c, "big.txt", b"x" * (10 * 1024 * 1024 + 1)).data)
        self.assertEqual(self.enc_files(), [])

    def test_path_traversal_filename(self):
        c = self.user_client("alice")
        self.upload(c, "../../evil.txt")
        self.assertEqual(self.query("SELECT original_filename FROM files")[0][0], "evil.txt")
        self.assertEqual(len(self.enc_files()), 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")))

    def test_08_sharing(self):
        a, b = self.user_client("alice"), self.user_client("bob")
        self.upload(a)
        r = self.share(a, 1, "bob")
        self.assertIn(b"Shared with bob", r.data)
        self.assertIn(b"report.txt", b.get("/shared").data)
        self.assertEqual(b.get("/download/1").data, CONTENT)             # bob decrypts with HIS private key
        keys = self.query("SELECT f.encrypted_aes_key AS a, s.encrypted_aes_key AS b FROM files f JOIN file_shares s ON s.file_id=f.id")[0]
        self.assertNotEqual(keys["a"], keys["b"])                        # key wrapped separately per user
        self.assertIn(b"No registered user", self.share(a, 1, "nobody").data)
        self.assertIn(b"Already shared", self.share(a, 1, "bob").data)

    def test_08b_revoke_share(self):
        a, b = self.user_client("alice"), self.user_client("bob")
        self.upload(a)
        self.share(a, 1, "bob")
        a.post("/unshare/1", data={"csrf_token": self.token(a, "/share/1"), "next_file": "1"})
        self.assertEqual(b.get("/download/1").status_code, 404)

    def test_09_unauthorized_access(self):
        a, b, c = self.user_client("alice"), self.user_client("bob"), self.user_client("carol")
        self.upload(a)
        self.share(a, 1, "bob")
        self.assertEqual(c.get("/download/1").status_code, 404)          # carol: no access
        self.assertEqual(c.get("/share/1").status_code, 404)
        self.assertEqual(b.get("/share/1").status_code, 404)             # recipient cannot re-share
        r = c.post("/delete/1", data={"csrf_token": self.token(c, "/files")})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(c.get("/download/999").status_code, 404)        # nonexistent looks identical
        anon = self.new_client()
        self.assertEqual(anon.get("/download/1").status_code, 302)       # not logged in -> login page
        denied = self.query("SELECT * FROM security_logs WHERE status='DENIED'")
        self.assertGreaterEqual(len(denied), 3)

    def test_10_modified_file_detected(self):
        a = self.user_client("alice")
        self.upload(a)
        path = self.enc_files()[0]
        data = bytearray(self.read_bytes(path))
        data[10] ^= 0x01                                                  # flip one bit
        self.write_bytes(path, bytes(data))
        r = a.get("/download/1", follow_redirects=True)
        self.assertIn(b"Integrity check failed", r.data)
        self.assertNotIn(b"TOP SECRET", r.data)
        fails = self.query("SELECT * FROM security_logs WHERE action LIKE 'FILE_DOWNLOAD%' AND status='FAILURE'")
        self.assertEqual(len(fails), 1)

    def test_12_security_logging(self):
        a = self.user_client("alice")
        self.upload(a)
        a.get("/download/1")
        self.login(self.new_client(), "alice", "bad-password1")
        a.post("/logout", data={"csrf_token": self.token(a, "/dashboard")})
        actions = [r["action"] for r in self.query("SELECT action FROM security_logs")]
        for expected in ("REGISTER", "LOGIN", "FILE_UPLOAD file_id=1", "FILE_DOWNLOAD file_id=1", "LOGOUT"):
            self.assertIn(expected, actions)
        row = self.query("SELECT * FROM security_logs WHERE action='LOGIN' AND status='FAILURE'")[0]
        self.assertTrue(row["ip_address"])
        self.assertTrue(row["timestamp"])


class TestCrypto(Base):
    def test_aes_gcm_roundtrip_and_tamper(self):
        key = cu.generate_aes_key()
        nonce, ct = cu.aes_encrypt(b"hello", key, b"aad")
        self.assertEqual(cu.aes_decrypt(ct, key, nonce, b"aad"), b"hello")
        with self.assertRaises(cu.DecryptionError):
            cu.aes_decrypt(ct[:-1] + bytes([ct[-1] ^ 1]), key, nonce, b"aad")
        with self.assertRaises(cu.DecryptionError):
            cu.aes_decrypt(ct, key, nonce, b"other-aad")

    def test_rsa_oaep_roundtrip_and_wrong_key(self):
        pub1, priv1 = cu.generate_rsa_keypair()
        _, priv2 = cu.generate_rsa_keypair()
        key = cu.generate_aes_key()
        wrapped = cu.rsa_encrypt_key(pub1, key)
        self.assertEqual(cu.rsa_decrypt_key(priv1, wrapped), key)
        with self.assertRaises(cu.DecryptionError):
            cu.rsa_decrypt_key(priv2, wrapped)

    def test_private_key_protection(self):
        _, priv = cu.generate_rsa_keypair()
        blob = cu.protect_private_key(priv, "pw-12345")
        self.assertEqual(cu.unlock_private_key(blob, "pw-12345"), priv)
        with self.assertRaises(cu.DecryptionError):
            cu.unlock_private_key(blob, "wrong")


if __name__ == "__main__":
    unittest.main(verbosity=2)
