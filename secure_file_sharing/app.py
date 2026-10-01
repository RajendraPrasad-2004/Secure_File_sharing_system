"""
app.py - Flask application: routes, security headers, error handling.

Run:  python app.py   ->  http://127.0.0.1:5000
"""
import io
import os
from datetime import timedelta

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, g, send_file, abort)

import config
import auth
import file_manager as fm
import crypto_utils as cu
from database import init_db, get_db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config)
    if test_config:
        app.config.update(test_config)
    app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or config.load_secret_key()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=app.config["PERMANENT_SESSION_LIFETIME_MINUTES"])
    os.makedirs(app.config["ENCRYPTED_DIR"], exist_ok=True)
    init_db(app)

    # ------------------------------------------------------- template helpers
    app.jinja_env.globals["csrf_token"] = auth.csrf_token

    @app.template_filter("filesize")
    def filesize(n):
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024

    @app.context_processor
    def inject_user():
        return {"current_user": g.get("user")}

    # ------------------------------------------------------ request pipeline
    @app.before_request
    def before():
        auth.load_current_user()
        if request.method == "POST" and not auth.csrf_is_valid():
            auth.log_event(session.get("user_id"), f"CSRF check failed {request.path}", "BLOCKED")
            abort(400, "Security token missing or invalid. Reload the page and try again.")

    @app.after_request
    def secure_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------ error pages
    def error_page(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(400)
    def e400(e):
        return error_page(400, "Request rejected", getattr(e, "description", "Bad request."))

    @app.errorhandler(403)
    def e403(e):
        return error_page(403, "Access denied", "You do not have permission to do that.")

    @app.errorhandler(404)
    def e404(e):
        return error_page(404, "Not found", "That page or file does not exist, or you cannot access it.")

    @app.errorhandler(413)
    def e413(e):
        return error_page(413, "File too large", "The upload exceeds the 10 MB limit.")

    @app.errorhandler(500)
    def e500(e):
        return error_page(500, "Something went wrong", "An internal error occurred. It has been logged.")

    # ----------------------------------------------------------------- routes
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            ok, err = auth.register_user(
                request.form.get("username", ""), request.form.get("email", ""),
                request.form.get("password", ""), request.form.get("confirm_password", ""))
            if ok:
                flash("Account created. Log in to continue.", "success")
                return redirect(url_for("login"))
            flash(err, "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            user, err = auth.authenticate(request.form.get("identifier", ""), request.form.get("password", ""))
            if user:
                return redirect(url_for("dashboard"))
            flash(err, "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        auth.logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @auth.login_required
    def dashboard():
        return render_template("dashboard.html", stats=fm.dashboard_stats(g.user["id"]))

    @app.route("/upload", methods=["GET", "POST"])
    @auth.login_required
    def upload():
        if request.method == "POST":
            ok, msg, file_id = fm.upload_file(g.user, request.files.get("file"))
            auth.log_event(g.user["id"], f"FILE_UPLOAD file_id={file_id}" if ok else "FILE_UPLOAD",
                           "SUCCESS" if ok else "FAILURE")
            flash(msg, "success" if ok else "error")
            return redirect(url_for("files" if ok else "upload"))
        return render_template("upload.html",
                               max_mb=app.config["MAX_FILE_SIZE"] // (1024 * 1024),
                               max_bytes=app.config["MAX_FILE_SIZE"],
                               extensions=sorted(app.config["ALLOWED_EXTENSIONS"]))

    @app.route("/files")
    @auth.login_required
    def files():
        return render_template("files.html", files=fm.list_my_files(g.user["id"]))

    @app.route("/shared")
    @auth.login_required
    def shared_files():
        return render_template("shared_files.html", files=fm.list_shared_with_me(g.user["id"]))

    @app.route("/download/<int:file_id>")
    @auth.login_required
    def download(file_id):
        uid = g.user["id"]
        try:
            name, data = fm.decrypt_file_for_user(file_id, uid, auth.get_private_key())
        except fm.AccessDenied:
            auth.log_event(uid, f"UNAUTHORIZED_DOWNLOAD file_id={file_id}", "DENIED")
            abort(404)      # same response as "missing" so ids cannot be probed
        except cu.DecryptionError:
            auth.log_event(uid, f"FILE_DOWNLOAD file_id={file_id} integrity check failed", "FAILURE")
            flash("Integrity check failed: this file was modified or corrupted, so it was not decrypted.", "error")
            return redirect(url_for("files"))
        except fm.FileMissing:
            auth.log_event(uid, f"FILE_DOWNLOAD file_id={file_id} missing on disk", "FAILURE")
            flash("The encrypted file is missing from storage.", "error")
            return redirect(url_for("files"))
        auth.log_event(uid, f"FILE_DOWNLOAD file_id={file_id}", "SUCCESS")
        return send_file(io.BytesIO(data), as_attachment=True, download_name=name,
                         mimetype="application/octet-stream")

    @app.route("/share/<int:file_id>", methods=["GET", "POST"])
    @auth.login_required
    def share(file_id):
        uid = g.user["id"]
        access = fm.get_access(file_id, uid)
        if access is None or access[2] != "owner":
            auth.log_event(uid, f"UNAUTHORIZED_SHARE file_id={file_id}", "DENIED")
            abort(404)
        if request.method == "POST":
            recipient = request.form.get("username", "")
            ok, msg = fm.share_file(file_id, g.user, recipient, auth.get_private_key())
            auth.log_event(uid, f"FILE_SHARE file_id={file_id} with={recipient[:30]}",
                           "SUCCESS" if ok else "FAILURE")
            flash(msg, "success" if ok else "error")
            return redirect(url_for("share", file_id=file_id))
        return render_template("share.html", file=access[0], recipients=fm.list_recipients(file_id, uid))

    @app.route("/unshare/<int:share_id>", methods=["POST"])
    @auth.login_required
    def unshare(share_id):
        ok = fm.revoke_share(share_id, g.user["id"])
        auth.log_event(g.user["id"], f"SHARE_REVOKE share_id={share_id}", "SUCCESS" if ok else "DENIED")
        if not ok:
            abort(404)
        flash("Access removed.", "success")
        next_file = request.form.get("next_file", "")
        if next_file.isdigit():
            return redirect(url_for("share", file_id=int(next_file)))
        return redirect(url_for("files"))

    @app.route("/delete/<int:file_id>", methods=["POST"])
    @auth.login_required
    def delete(file_id):
        try:
            name = fm.delete_file(file_id, g.user["id"])
        except fm.AccessDenied:
            auth.log_event(g.user["id"], f"UNAUTHORIZED_DELETE file_id={file_id}", "DENIED")
            abort(404)
        auth.log_event(g.user["id"], f"FILE_DELETE file_id={file_id}", "SUCCESS")
        flash(f"'{name}' was deleted.", "success")
        return redirect(url_for("files"))

    @app.route("/logs")
    @auth.login_required
    def logs():
        rows = get_db().execute(
            "SELECT * FROM security_logs WHERE user_id = ? ORDER BY id DESC LIMIT 100", (g.user["id"],)).fetchall()
        return render_template("logs.html", logs=rows)

    return app


if __name__ == "__main__":
    # debug=False: the Werkzeug debugger must never be exposed in a security project.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
