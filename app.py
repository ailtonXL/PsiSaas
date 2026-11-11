import csv
import io
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from domain import appointment_input, check_conflicts, insert_appointment, migrate
from features import register_features
from decimal import InvalidOperation
from functools import wraps
from urllib.parse import urlencode

import click
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
)
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE", "instance/psi.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    for key in (
        "PUBLIC_BASE_URL",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASSWORD",
        "MAIL_FROM",
        "WA_PHONE_ID",
        "WA_ACCESS_TOKEN",
        "WA_TEMPLATE",
        "MP_ACCESS_TOKEN",
        "MP_WEBHOOK_SECRET",
        "MP_OWNER_EMAIL",
        "BACKUP_KEY",
        "MFA_KEY",
    ):
        app.config[key] = os.environ.get(key, "")
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "Configure SECRET_KEY com um segredo aleatório de pelo menos 32 caracteres."
        )
    if len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY deve ter pelo menos 32 caracteres.")
    os.makedirs(os.path.dirname(os.path.abspath(app.config["DATABASE"])), exist_ok=True)

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")
        return g.db

    @app.teardown_appcontext
    def close_db(error):
        if "db" in g:
            g.db.close()

    with app.app_context():
        db().executescript(
            """
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS patients(id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', waiting INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id), patient INTEGER NOT NULL REFERENCES patients(id), start TEXT NOT NULL, duration INTEGER NOT NULL, amount INTEGER NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Agendada', paid INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY, count INTEGER NOT NULL, since INTEGER NOT NULL);
        """
        )
        migrate(db())

    def authenticated(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login"))
            return fn(*args, **kwargs)

        return wrapped

    @app.before_request
    def security():
        g.user = (
            db()
            .execute("SELECT * FROM users WHERE id=?", (session.get("uid"),))
            .fetchone()
        )
        if g.user and session.get("version", 0) != g.user["session_version"]:
            session.clear()
            g.user = None
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if (
            request.endpoint != "mp_webhook"
            and request.method == "POST"
            and not secrets.compare_digest(
                request.form.get("csrf", ""), session["csrf"]
            )
        ):
            abort(400, "Formulário expirado. Atualize a página.")

    @app.after_request
    def headers(response):
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            }
        )
        return response

    @app.template_filter("money")
    def money(cents):
        return "R$ " + f"{cents/100:,.2f}".replace(",", "_").replace(".", ",").replace(
            "_", "."
        )

    @app.template_filter("datebr")
    def datebr(value):
        return datetime.fromisoformat(value).strftime("%d/%m/%Y às %H:%M")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            key = (request.remote_addr or "") + ":" + email
            now = int(datetime.now().timestamp())
            attempt = (
                db().execute("SELECT * FROM attempts WHERE key=?", (key,)).fetchone()
            )
            if attempt and attempt["count"] >= 5 and now - attempt["since"] < 900:
                return (
                    render_template(
                        "login.html", error="Muitas tentativas. Aguarde 15 minutos."
                    ),
                    429,
                )
            user = (
                db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            )
            if user and check_password_hash(
                user["password"], request.form.get("password", "")
            ):
                if user["totp_secret"]:
                    session.clear()
                    session.update(
                        mfa_uid=user["id"],
                        mfa_version=user["session_version"],
                        mfa_expires=int(datetime.now().timestamp()) + 300,
                        csrf=secrets.token_urlsafe(32),
                    )
                    return redirect(url_for("mfa_login"))
                db().execute("DELETE FROM attempts WHERE key=?", (key,))
                db().commit()
                session.clear()
                session.update(
                    uid=user["id"],
                    version=user["session_version"],
                    csrf=secrets.token_urlsafe(32),
                )
                session.permanent = True
                return redirect(url_for("home"))
            count = (
                attempt["count"] + 1 if attempt and now - attempt["since"] < 900 else 1
            )
            since = attempt["since"] if count > 1 else now
            db().execute(
                "INSERT OR REPLACE INTO attempts VALUES(?,?,?)", (key, count, since)
            )
            db().commit()
            return (
                render_template("login.html", error="E-mail ou senha inválidos."),
                401,
            )
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    def rows():
        return (
            db()
            .execute(
                "SELECT a.*,p.name,p.phone FROM appointments a JOIN patients p ON p.id=a.patient WHERE a.owner=? ORDER BY start",
                (g.user["id"],),
            )
            .fetchall()
        )

    @app.get("/")
    @authenticated
    def home():
        all_rows = rows()
        today = datetime.now().date().isoformat()
        month = today[:7]
        active = [r for r in all_rows if r["status"] != "Cancelada"]
        return render_template(
            "home.html",
            page="Visão geral",
            today=today,
            appointments=[r for r in active if r["start"][:10] == today],
            received=sum(
                r["amount"]
                for r in active
                if r["paid"] and r["start"].startswith(month)
            ),
            pending=sum(
                r["amount"]
                for r in active
                if not r["paid"] and r["start"].startswith(month)
            ),
            patients_count=db()
            .execute("SELECT COUNT(*) FROM patients WHERE owner=?", (g.user["id"],))
            .fetchone()[0],
        )

    @app.route("/pacientes", methods=["GET", "POST"])
    @authenticated
    def patients():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            phone = "".join(
                c for c in request.form.get("phone", "") if c.isascii() and c.isdigit()
            )
            email = request.form.get("email", "").strip()
            if (
                not name
                or len(name) > 120
                or len(phone) > 15
                or len(email) > 180
                or (email and "@" not in email)
            ):
                flash("Confira nome, telefone e e-mail.", "error")
            else:
                db().execute(
                    "INSERT INTO patients(owner,name,phone,email,waiting,reminder_consent) VALUES(?,?,?,?,?,?)",
                    (
                        g.user["id"],
                        name,
                        phone,
                        email,
                        int(request.form.get("waiting") == "on"),
                        int(request.form.get("consent") == "on"),
                    ),
                )
                db().commit()
                flash("Paciente cadastrado.", "success")
            return redirect(url_for("patients"))
        q = request.args.get("q", "").strip()
        data = (
            db()
            .execute(
                "SELECT * FROM patients WHERE owner=? AND name LIKE ? ORDER BY name",
                (g.user["id"], "%" + q + "%"),
            )
            .fetchall()
        )
        return render_template("patients.html", page="Pacientes", patients=data, q=q)

    @app.post("/pacientes/<int:pid>/espera")
    @authenticated
    def waiting(pid):
        result = db().execute(
            "UPDATE patients SET waiting=1-waiting WHERE id=? AND owner=?",
            (pid, g.user["id"]),
        )
        if not result.rowcount:
            abort(404)
        db().commit()
        return redirect(url_for("patients"))

    @app.route("/agenda", methods=["GET", "POST"])
    @authenticated
    def agenda():
        if request.method == "POST":
            try:
                pid = int(request.form["patient"])
                if (
                    not db()
                    .execute(
                        "SELECT id FROM patients WHERE id=? AND owner=?",
                        (pid, g.user["id"]),
                    )
                    .fetchone()
                ):
                    raise ValueError()
                start, duration, amount, mode = appointment_input(request.form)
                repeat = int(request.form.get("repeat", "1"))
                if not 1 <= repeat <= 52:
                    raise ValueError()
                proposed = [
                    (start + timedelta(weeks=i), duration) for i in range(repeat)
                ]
                db().execute("BEGIN IMMEDIATE")
                check_conflicts(db(), g.user["id"], proposed)
                series = secrets.token_urlsafe(16) if repeat > 1 else None
                for when, length in proposed:
                    insert_appointment(
                        db(), g.user["id"], pid, when, length, amount, mode, series
                    )
                db().commit()
                flash("Sessão agendada.", "success")
            except (ValueError, KeyError, InvalidOperation, OverflowError) as error:
                db().rollback()
                flash(
                    (
                        str(error)
                        if str(error) == "Já existe uma sessão nesse horário."
                        else "Confira paciente, data, duração e valor."
                    ),
                    "error",
                )
            return redirect(url_for("agenda"))
        selected = request.args.get("date", "")
        data = [r for r in rows() if not selected or r["start"][:10] == selected]
        return render_template(
            "agenda.html",
            page="Agenda",
            appointments=data,
            patients=db()
            .execute(
                "SELECT * FROM patients WHERE owner=? ORDER BY name", (g.user["id"],)
            )
            .fetchall(),
            selected=selected,
        )

    @app.post("/sessoes/<int:aid>/atualizar")
    @authenticated
    def update(aid):
        db().execute("BEGIN IMMEDIATE")
        row = (
            db()
            .execute(
                "SELECT * FROM appointments WHERE id=? AND owner=?", (aid, g.user["id"])
            )
            .fetchone()
        )
        if not row:
            abort(404)
        action = request.form.get("action")
        if action == "paid":
            if row["status"] == "Cancelada":
                abort(400)
            if row["payment_key"]:
                flash(
                    "Pagamentos Pix devem ser conferidos e estornados no provedor.",
                    "error",
                )
                return redirect(url_for("finance"))
            paid_at = request.form.get("paid_at") or datetime.now().date().isoformat()
            try:
                datetime.strptime(paid_at, "%Y-%m-%d")
            except ValueError:
                abort(400)
            if paid_at > datetime.now().date().isoformat():
                abort(400)
            db().execute(
                "UPDATE appointments SET paid=1-paid,paid_at=? WHERE id=?",
                (paid_at if not row["paid"] else None, aid),
            )
        elif action in ("Agendada", "Confirmada", "Realizada", "Faltou", "Cancelada"):
            if action == "Cancelada" and row["paid"]:
                flash("Estorne o pagamento antes de cancelar a sessão.", "error")
                return redirect(url_for("agenda"))
            if row["status"] == "Cancelada" and action != "Cancelada":
                try:
                    check_conflicts(
                        db(),
                        g.user["id"],
                        [(datetime.fromisoformat(row["start"]), row["duration"])],
                        (aid,),
                    )
                except ValueError:
                    flash("Já existe uma sessão nesse horário.", "error")
                    return redirect(url_for("agenda"))
            if row["payment_key"] and action == "Cancelada":
                flash("Resolva a cobrança Pix no provedor antes de cancelar.", "error")
                return redirect(url_for("agenda"))
            db().execute("UPDATE appointments SET status=? WHERE id=?", (action, aid))
        else:
            abort(400)
        db().commit()
        return redirect(
            url_for("finance" if request.form.get("source") == "finance" else "agenda")
        )

    @app.get("/financeiro/exportar")
    @authenticated
    def export():
        out = io.StringIO()
        writer = csv.writer(out, delimiter=";")
        writer.writerow(
            [
                "Data",
                "Paciente",
                "Valor (BRL)",
                "Pagamento",
                "Situação",
                "Data do recebimento",
            ]
        )
        for r in rows():
            # Prevent spreadsheet formula injection in patient-controlled fields.
            name = r["name"]
            name = (
                "'" + name if name.lstrip().startswith(("=", "+", "-", "@")) else name
            )
            writer.writerow(
                [
                    r["start"],
                    name,
                    f"{r['amount']/100:.2f}",
                    "Pago" if r["paid"] else "Pendente",
                    r["status"],
                    r["paid_at"] or "",
                ]
            )
        return Response(
            "\ufeff" + out.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=financeiro.csv"},
        )

    @app.get("/lembrete/<int:aid>")
    @authenticated
    def reminder(aid):
        row = (
            db()
            .execute(
                "SELECT a.*,p.name,p.phone FROM appointments a JOIN patients p ON p.id=a.patient WHERE a.id=? AND a.owner=?",
                (aid, g.user["id"]),
            )
            .fetchone()
        )
        if not row:
            abort(404)
        if not row["phone"] or row["status"] == "Cancelada":
            abort(400)
        phone = row["phone"]
        phone = phone if phone.startswith("55") and len(phone) >= 12 else "55" + phone
        message = f"Olá, {row['name']}. Lembrete do seu horário em {datebr(row['start'])}. Pode confirmar sua presença?"
        if request.args.get("payment") == "1":
            if row["paid"]:
                abort(400)
            message = f"Olá, {row['name']}. Há um pagamento de {money(row['amount'])} pendente referente ao horário de {datebr(row['start'])}. Podemos conferir?"
        return redirect("https://wa.me/" + phone + "?" + urlencode({"text": message}))

    @app.cli.command("create-user")
    @click.option("--email", prompt=True)
    @click.option("--name", prompt="Nome")
    @click.password_option()
    def create_user(email, name, password):
        if len(password) < 12:
            raise click.ClickException("Use uma senha com pelo menos 12 caracteres.")
        if "@" not in email or not name.strip():
            raise click.ClickException("Nome e e-mail inválidos.")
        try:
            db().execute(
                "INSERT INTO users(email,name,password) VALUES(?,?,?)",
                (email.strip().lower(), name.strip(), generate_password_hash(password)),
            )
            db().commit()
        except sqlite3.IntegrityError:
            raise click.ClickException("E-mail já cadastrado.")
        click.echo("Usuário criado.")

    register_features(app, db, authenticated, rows)
    return app
