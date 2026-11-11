"""Account recovery, TOTP and encrypted SQLite backup/restore."""

import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import struct
import time
from urllib.parse import quote

import click
from cryptography.fernet import Fernet, InvalidToken
from flask import abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import integrations


def totp(secret, step=None):
    step = int(time.time()) // 30 if step is None else step
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'


def verify_totp(secret, code, last=-1):
    if len(code) != 6 or not code.isdigit():
        return None
    step = int(time.time()) // 30
    for offset in (-1, 0, 1):
        candidate = step + offset
        if candidate > last and hmac.compare_digest(totp(secret, candidate), code):
            return candidate
    return None


def register_security(app, db, authenticated):
    def cipher(key="MFA_KEY"):
        value = app.config.get(key)
        if not value:
            raise ValueError("Configure " + key + " com uma chave Fernet.")
        return Fernet(value.encode())

    def limited(key, limit=5):
        now = int(time.time())
        db().execute("BEGIN IMMEDIATE")
        row = db().execute("SELECT * FROM attempts WHERE key=?", (key,)).fetchone()
        count = row["count"] + 1 if row and now - row["since"] < 900 else 1
        since = row["since"] if count > 1 else now
        db().execute(
            "INSERT OR REPLACE INTO attempts VALUES(?,?,?)", (key, count, since)
        )
        db().commit()
        return count > limit

    @app.route("/recuperar", methods=["GET", "POST"])
    def forgot():
        if request.method == "POST":
            if limited("reset-ip:" + (request.remote_addr or ""), 5):
                abort(429)
            email = request.form.get("email", "").strip().lower()
            user = (
                db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            )
            if (
                user
                and app.config.get("SMTP_HOST")
                and app.config.get("PUBLIC_BASE_URL", "").startswith("https://")
            ):
                token = secrets.token_urlsafe(32)
                digest = hashlib.sha256(token.encode()).hexdigest()
                db().execute(
                    "DELETE FROM reset_tokens WHERE user=? OR expires<?",
                    (user["id"], int(time.time())),
                )
                db().execute(
                    "INSERT INTO reset_tokens VALUES(?,?,?)",
                    (digest, user["id"], int(time.time()) + 1800),
                )
                db().commit()
                link = app.config["PUBLIC_BASE_URL"].rstrip("/") + url_for(
                    "reset_password", token=token
                )
                try:
                    integrations.send_mail(
                        app.config,
                        email,
                        "Recuperar acesso ao PsiSaas",
                        "Use este link em até 30 minutos: "
                        + link
                        + "\nSe não solicitou, ignore esta mensagem.",
                    )
                except (OSError, RuntimeError):
                    pass
            flash(
                "Se o endereço estiver cadastrado e o envio configurado, você receberá um link de recuperação.",
                "success",
            )
        return render_template(
            "account_form.html",
            page="Recuperar acesso",
            title="Recuperar acesso",
            kind="forgot",
        )

    @app.route("/redefinir/<token>", methods=["GET", "POST"])
    def reset_password(token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = (
            db()
            .execute(
                "SELECT * FROM reset_tokens WHERE digest=? AND expires>?",
                (digest, int(time.time())),
            )
            .fetchone()
        )
        if not row:
            abort(410)
        if request.method == "POST":
            password = request.form.get("password", "")
            if len(password) < 12 or password != request.form.get("confirm"):
                flash("Use pelo menos 12 caracteres e confirme a mesma senha.", "error")
            else:
                db().execute("BEGIN IMMEDIATE")
                result = db().execute(
                    "DELETE FROM reset_tokens WHERE digest=? AND expires>?",
                    (digest, int(time.time())),
                )
                if not result.rowcount:
                    abort(410)
                db().execute(
                    "UPDATE users SET password=?,session_version=session_version+1 WHERE id=?",
                    (generate_password_hash(password), row["user"]),
                )
                db().execute("DELETE FROM reset_tokens WHERE user=?", (row["user"],))
                db().commit()
                session.clear()
                flash("Senha alterada. Entre novamente.", "success")
                return redirect(url_for("login"))
        return render_template(
            "account_form.html",
            page="Redefinir senha",
            title="Escolha sua nova senha",
            kind="reset",
        )

    @app.route("/login/codigo", methods=["GET", "POST"])
    def mfa_login():
        uid = session.get("mfa_uid")
        if not uid or session.get("mfa_expires", 0) < time.time():
            return redirect(url_for("login"))
        user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if (
            not user
            or not user["totp_secret"]
            or session.get("mfa_version") != user["session_version"]
        ):
            return redirect(url_for("login"))
        if request.method == "POST":
            if limited("mfa:" + str(uid)):
                abort(429)
            try:
                secret = cipher().decrypt(user["totp_secret"].encode()).decode()
            except (ValueError, InvalidToken):
                abort(503)
            step = verify_totp(secret, request.form.get("code", ""), user["totp_last"])
            if step is not None:
                result = db().execute(
                    "UPDATE users SET totp_last=? WHERE id=? AND totp_last<?",
                    (step, uid, step),
                )
                db().commit()
                if not result.rowcount:
                    abort(401)
                session.clear()
                session.update(
                    uid=uid,
                    version=user["session_version"],
                    csrf=secrets.token_urlsafe(32),
                )
                session.permanent = True
                return redirect(url_for("home"))
            flash("Código inválido ou já utilizado.", "error")
        return render_template(
            "account_form.html",
            page="Verificar acesso",
            title="Verificação em duas etapas",
            kind="mfa",
        )

    @app.route("/conta", methods=["GET", "POST"])
    @authenticated
    def account():
        if request.method == "POST":
            if limited("account:" + str(g.user["id"])):
                abort(429)
            if not check_password_hash(
                g.user["password"], request.form.get("password", "")
            ):
                flash("Senha incorreta.", "error")
                return redirect(url_for("account"))
            action = request.form.get("action")
            if action in ("prepare", "enable") and g.user["totp_secret"]:
                abort(400)
            if action == "prepare":
                try:
                    cipher()
                except ValueError as error:
                    flash(str(error), "error")
                    return redirect(url_for("account"))
                session["totp_pending"] = (
                    base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
                )
                session["totp_pending_expires"] = int(time.time()) + 600
            elif action == "enable":
                secret = session.get("totp_pending", "")
                if not secret or session.get("totp_pending_expires", 0) < time.time():
                    abort(400)
                step = verify_totp(secret, request.form.get("code", ""))
                if step is None:
                    flash("Código inválido.", "error")
                    return redirect(url_for("account"))
                result = db().execute(
                    "UPDATE users SET totp_secret=?,totp_last=?,session_version=session_version+1 WHERE id=? AND totp_secret IS NULL",
                    (cipher().encrypt(secret.encode()).decode(), step, g.user["id"]),
                )
                db().commit()
                if not result.rowcount:
                    abort(409)
                session["version"] = g.user["session_version"] + 1
                session.pop("totp_pending", None)
                flash("Verificação em duas etapas ativada.", "success")
                return redirect(url_for("account"))
            elif action == "disable":
                if g.user["totp_secret"]:
                    try:
                        secret = (
                            cipher().decrypt(g.user["totp_secret"].encode()).decode()
                        )
                    except (ValueError, InvalidToken):
                        abort(503)
                    if (
                        verify_totp(
                            secret, request.form.get("code", ""), g.user["totp_last"]
                        )
                        is None
                    ):
                        flash("Código inválido.", "error")
                        return redirect(url_for("account"))
                db().execute(
                    "UPDATE users SET totp_secret=NULL,totp_last=-1,session_version=session_version+1 WHERE id=?",
                    (g.user["id"],),
                )
                db().commit()
                session["version"] = g.user["session_version"] + 1
                session.pop("totp_pending", None)
                return redirect(url_for("account"))
            else:
                abort(400)
        secret = (
            session.get("totp_pending")
            if session.get("totp_pending_expires", 0) > time.time()
            else None
        )
        uri = (
            "otpauth://totp/"
            + quote("PsiSaas:" + g.user["email"])
            + "?secret="
            + secret
            + "&issuer=PsiSaas"
            if secret
            else None
        )
        return render_template(
            "account.html", page="Minha conta", secret=secret, uri=uri
        )

    @app.cli.command("disable-mfa")
    @click.option("--email", required=True)
    @click.confirmation_option(
        prompt="Identidade do titular verificada fora do sistema?"
    )
    def disable_mfa(email):
        result = db().execute(
            "UPDATE users SET totp_secret=NULL,totp_last=-1,session_version=session_version+1 WHERE email=?",
            (email.strip().lower(),),
        )
        db().commit()
        if not result.rowcount:
            raise click.ClickException("Conta não encontrada.")
        click.echo("MFA removido e sessões invalidadas.")

    @app.cli.command("backup")
    @click.argument("destination", type=click.Path())
    def backup(destination):
        try:
            encryption = cipher("BACKUP_KEY")
        except ValueError as error:
            raise click.ClickException(str(error))
        snapshot = sqlite3.connect(":memory:")
        db().backup(snapshot)
        content = snapshot.serialize()
        snapshot.close()
        encrypted = encryption.encrypt(content)
        # Exclusive creation avoids accidentally overwriting a previous backup.
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encrypted)
        click.echo("Backup criptografado criado.")

    @app.cli.command("restore-backup")
    @click.argument("source", type=click.Path(exists=True))
    @click.argument("destination", type=click.Path())
    def restore(source, destination):
        """Restore into a NEW database. Stop the service before switching files."""
        try:
            content = cipher("BACKUP_KEY").decrypt(Path(source).read_bytes())
            restored = sqlite3.connect(":memory:")
            restored.deserialize(content)
            if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Integridade inválida.")
            required = {"users", "patients", "appointments"}
            tables = {
                r[0]
                for r in restored.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not required <= tables:
                raise ValueError("Banco inválido.")
        except (InvalidToken, ValueError, sqlite3.DatabaseError):
            raise click.ClickException("Backup ou chave inválidos.")
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        target = sqlite3.connect(destination)
        restored.backup(target)
        target.close()
        restored.close()
        click.echo("Backup restaurado em novo arquivo e integridade validada.")
