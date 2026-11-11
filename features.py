import calendar
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta
from decimal import Decimal
from urllib.error import URLError

import click
from flask import (
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
    Response,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from domain import appointment_input, cents, check_conflicts, insert_appointment
import integrations
from security import register_security


def register_features(app, db, authenticated, rows):
    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"], salt="patient-confirmation"
    )

    def public_base():
        base = app.config.get("PUBLIC_BASE_URL", "").rstrip("/")
        if not base.startswith("https://"):
            raise ValueError(
                "Configure PUBLIC_BASE_URL com o endereço HTTPS da aplicação."
            )
        return base

    def confirmation_link(row):
        token = serializer.dumps(
            {"id": row["id"], "nonce": row["confirmation_nonce"], "start": row["start"]}
        )
        return public_base() + "/confirmar/" + token

    def owned(table, rid):
        if table not in ("patients", "appointments", "expenses"):
            abort(400)
        row = (
            db()
            .execute(
                f"SELECT * FROM {table} WHERE id=? AND owner=?", (rid, g.user["id"])
            )
            .fetchone()
        )
        if not row:
            abort(404)
        return row

    def payment_ready():
        return bool(
            app.config.get("MP_ACCESS_TOKEN")
            and app.config.get("MP_WEBHOOK_SECRET")
            and app.config.get("PUBLIC_BASE_URL")
            and g.user
            and g.user["email"] == app.config.get("MP_OWNER_EMAIL")
        )

    @app.context_processor
    def feature_context():
        return {
            "pix_enabled": payment_ready(),
            "automatic_reminders": bool(
                app.config.get("PUBLIC_BASE_URL")
                and (app.config.get("SMTP_HOST") or app.config.get("WA_ACCESS_TOKEN"))
            ),
        }

    @app.route("/pacientes/<int:pid>/editar", methods=["GET", "POST"])
    @authenticated
    def patient_edit(pid):
        patient = owned("patients", pid)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            phone = "".join(
                c for c in request.form.get("phone", "") if c.isascii() and c.isdigit()
            )
            if (
                not name
                or len(name) > 120
                or len(email) > 180
                or (email and "@" not in email)
                or len(phone) > 15
            ):
                flash("Confira nome, telefone e e-mail.", "error")
            else:
                db().execute(
                    "UPDATE patients SET name=?,email=?,phone=?,reminder_consent=? WHERE id=?",
                    (name, email, phone, int(request.form.get("consent") == "on"), pid),
                )
                db().commit()
                flash("Paciente atualizado.", "success")
                return redirect(url_for("patients"))
        return render_template(
            "patient_edit.html", page="Editar paciente", patient=patient
        )

    @app.get("/pacientes/<int:pid>/exportar")
    @authenticated
    def patient_export(pid):
        patient = owned("patients", pid)
        data = {
            "paciente": dict(patient),
            "sessoes": [
                dict(r)
                for r in db().execute(
                    "SELECT id,start,duration,amount,mode,status,paid,paid_at FROM appointments WHERE patient=? AND owner=?",
                    (pid, g.user["id"]),
                )
            ],
        }
        data["paciente"].pop("owner")
        return Response(
            json.dumps(data, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=paciente-{pid}.json"
            },
        )

    @app.post("/pacientes/<int:pid>/excluir")
    @authenticated
    def patient_delete(pid):
        owned("patients", pid)
        if request.form.get("confirm") != "EXCLUIR":
            abort(400)
        db().execute("BEGIN IMMEDIATE")
        if (
            db()
            .execute(
                "SELECT 1 FROM appointments WHERE patient=? AND payment_key IS NOT NULL",
                (pid,),
            )
            .fetchone()
        ):
            flash(
                "Concilie e desvincule as cobranças Pix antes de excluir este paciente.",
                "error",
            )
            return redirect(url_for("patient_edit", pid=pid))
        db().execute(
            "DELETE FROM deliveries WHERE appointment IN (SELECT id FROM appointments WHERE patient=?)",
            (pid,),
        )
        db().execute(
            "DELETE FROM offers WHERE patient=? OR appointment IN (SELECT id FROM appointments WHERE patient=?)",
            (pid, pid),
        )
        db().execute(
            "DELETE FROM appointments WHERE patient=? AND owner=?", (pid, g.user["id"])
        )
        db().execute("DELETE FROM patients WHERE id=? AND owner=?", (pid, g.user["id"]))
        db().commit()
        flash("Paciente e seus registros foram excluídos.", "success")
        return redirect(url_for("patients"))

    @app.route("/sessoes/<int:aid>/editar", methods=["GET", "POST"])
    @authenticated
    def appointment_edit(aid):
        current = owned("appointments", aid)
        patients = (
            db()
            .execute(
                "SELECT * FROM patients WHERE owner=? ORDER BY name", (g.user["id"],)
            )
            .fetchall()
        )
        if request.method == "POST":
            try:
                start, duration, amount, mode = appointment_input(request.form)
                pid = int(request.form["patient"])
                owned("patients", pid)
                db().execute("BEGIN IMMEDIATE")
                current = owned("appointments", aid)
                if current["status"] == "Cancelada":
                    raise ValueError("Sessões canceladas não podem ser reagendadas.")
                if request.form.get("scope") == "series" and current["series_id"]:
                    targets = (
                        db()
                        .execute(
                            "SELECT * FROM appointments WHERE owner=? AND series_id=? AND start>=? AND status!='Cancelada' ORDER BY start",
                            (g.user["id"], current["series_id"], current["start"]),
                        )
                        .fetchall()
                    )
                else:
                    targets = [current]
                if any(
                    r["paid"]
                    or r["payment_key"]
                    or r["status"] in ("Realizada", "Faltou")
                    for r in targets
                ):
                    raise ValueError(
                        "Não é possível alterar sessões realizadas, com falta, pagas ou com cobrança Pix ativa."
                    )
                delta = start - datetime.fromisoformat(current["start"])
                proposed = [
                    (datetime.fromisoformat(r["start"]) + delta, duration)
                    for r in targets
                ]
                check_conflicts(
                    db(), g.user["id"], proposed, [r["id"] for r in targets]
                )
                for row, (when, length) in zip(targets, proposed):
                    db().execute(
                        "UPDATE appointments SET patient=?,start=?,duration=?,amount=?,mode=?,status='Agendada',confirmation_nonce=? WHERE id=?",
                        (
                            pid,
                            when.isoformat(timespec="minutes"),
                            length,
                            amount,
                            mode,
                            secrets.token_urlsafe(24),
                            row["id"],
                        ),
                    )
                    db().execute(
                        "UPDATE offers SET status='Encerrada' WHERE appointment=?",
                        (row["id"],),
                    )
                db().execute("UPDATE patients SET waiting=0 WHERE id=?", (pid,))
                db().commit()
                flash(f"{len(targets)} sessão(ões) atualizada(s).", "success")
                return redirect(url_for("agenda"))
            except (ValueError, KeyError, OverflowError) as error:
                db().rollback()
                flash(str(error) or "Confira os dados da sessão.", "error")
        return render_template(
            "appointment_edit.html",
            page="Reagendar sessão",
            a=current,
            patients=patients,
        )

    @app.route("/confirmar/<token>", methods=["GET", "POST"])
    def confirm(token):
        try:
            data = serializer.loads(token, max_age=7 * 86400)
            row = (
                db()
                .execute("SELECT * FROM appointments WHERE id=?", (data["id"],))
                .fetchone()
            )
            if (
                not row
                or row["confirmation_nonce"] != data["nonce"]
                or row["start"] != data["start"]
            ):
                abort(410)
        except (BadSignature, SignatureExpired, KeyError):
            abort(410)
        if (
            row["status"] not in ("Agendada", "Confirmada")
            or datetime.fromisoformat(row["start"]) <= datetime.now()
        ):
            abort(410)
        if request.method == "POST":
            result = db().execute(
                "UPDATE appointments SET status='Confirmada' WHERE id=? AND confirmation_nonce=? AND start=? AND status IN ('Agendada','Confirmada')",
                (row["id"], data["nonce"], data["start"]),
            )
            if not result.rowcount:
                abort(410)
            db().commit()
            return render_template(
                "public.html",
                page="Presença confirmada",
                title="Presença confirmada!",
                message="Seu horário está confirmado. Até breve.",
            )
        return render_template(
            "public.html",
            page="Confirmar presença",
            title="Confirme seu horário",
            message="Horário: " + app.jinja_env.filters["datebr"](row["start"]),
            button="Confirmar presença",
        )

    @app.get("/sessoes/<int:aid>/confirmacao")
    @authenticated
    def confirmation(aid):
        row = owned("appointments", aid)
        try:
            link = confirmation_link(row)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("agenda"))
        return render_template(
            "link.html",
            page="Link de confirmação",
            title="Confirmação de presença",
            link=link,
        )

    @app.route("/sessoes/<int:aid>/ofertas", methods=["GET", "POST"])
    @authenticated
    def offers(aid):
        row = owned("appointments", aid)
        if (
            row["status"] != "Cancelada"
            or datetime.fromisoformat(row["start"]) <= datetime.now()
        ):
            abort(400)
        waitlist = (
            db()
            .execute(
                "SELECT * FROM patients WHERE owner=? AND waiting=1 ORDER BY id",
                (g.user["id"],),
            )
            .fetchall()
        )
        link = None
        if request.method == "POST":
            patient = owned("patients", request.form.get("patient", 0))
            if not patient["waiting"]:
                abort(400)
            try:
                base = public_base()
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("offers", aid=aid))
            token = secrets.token_urlsafe(32)
            expires = min(
                datetime.now() + timedelta(hours=24),
                datetime.fromisoformat(row["start"]),
            ).isoformat()
            db().execute(
                "INSERT INTO offers(token,owner,appointment,patient,expires) VALUES(?,?,?,?,?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    g.user["id"],
                    aid,
                    patient["id"],
                    expires,
                ),
            )
            db().commit()
            link = base + url_for("accept_offer", token=token)
        return render_template(
            "offers.html", page="Preencher vaga", a=row, patients=waitlist, link=link
        )

    @app.route("/vaga/<token>", methods=["GET", "POST"])
    def accept_offer(token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        if request.method == "POST":
            db().execute("BEGIN IMMEDIATE")
        offer = db().execute("SELECT * FROM offers WHERE token=?", (digest,)).fetchone()
        if (
            not offer
            or offer["status"] != "Aberta"
            or datetime.fromisoformat(offer["expires"]) <= datetime.now()
        ):
            abort(410)
        row = (
            db()
            .execute("SELECT * FROM appointments WHERE id=?", (offer["appointment"],))
            .fetchone()
        )
        if (
            row["status"] != "Cancelada"
            or datetime.fromisoformat(row["start"]) <= datetime.now()
        ):
            abort(410)
        if request.method == "POST":
            try:
                check_conflicts(
                    db(),
                    offer["owner"],
                    [(datetime.fromisoformat(row["start"]), row["duration"])],
                )
            except ValueError:
                db().rollback()
                abort(409, "Este horário já foi preenchido.")
            new_id = insert_appointment(
                db(),
                offer["owner"],
                offer["patient"],
                datetime.fromisoformat(row["start"]),
                row["duration"],
                row["amount"],
                row["mode"],
            )
            db().execute(
                "UPDATE appointments SET status='Confirmada' WHERE id=?", (new_id,)
            )
            db().execute(
                "UPDATE offers SET status='Encerrada' WHERE appointment=?", (row["id"],)
            )
            db().execute("UPDATE offers SET status='Aceita' WHERE id=?", (offer["id"],))
            db().commit()
            return render_template(
                "public.html",
                page="Horário reservado",
                title="Horário reservado!",
                message="Sua presença está confirmada.",
            )
        return render_template(
            "public.html",
            page="Horário disponível",
            title="Um horário está disponível",
            message=app.jinja_env.filters["datebr"](row["start"])
            + " · "
            + str(row["duration"])
            + " minutos · "
            + app.jinja_env.filters["money"](row["amount"])
            + " · "
            + row["mode"],
            button="Aceitar e confirmar horário",
        )

    @app.get("/financeiro")
    @authenticated
    def finance():
        month = request.args.get("month", datetime.now().strftime("%Y-%m"))
        try:
            if datetime.strptime(month, "%Y-%m").strftime("%Y-%m") != month:
                raise ValueError()
        except ValueError:
            abort(400)
        data = [
            r
            for r in rows()
            if r["start"].startswith(month) and r["status"] != "Cancelada"
        ]
        expenses = (
            db()
            .execute(
                "SELECT * FROM expenses WHERE owner=? AND date LIKE ? ORDER BY date",
                (g.user["id"], month + "%"),
            )
            .fetchall()
        )
        cash = (
            db()
            .execute(
                "SELECT COALESCE(SUM(amount),0) FROM appointments WHERE owner=? AND paid=1 AND paid_at LIKE ?",
                (g.user["id"], month + "%"),
            )
            .fetchone()[0]
        )
        expense_total = sum(e["amount"] for e in expenses)
        unknown = (
            db()
            .execute(
                "SELECT COUNT(*) FROM appointments WHERE owner=? AND paid=1 AND paid_at IS NULL",
                (g.user["id"],),
            )
            .fetchone()[0]
        )
        return render_template(
            "finance.html",
            page="Financeiro",
            appointments=data,
            month=month,
            received=sum(r["amount"] for r in data if r["paid"]),
            pending=sum(r["amount"] for r in data if not r["paid"]),
            cash=cash,
            expenses=expenses,
            expense_total=expense_total,
            result=cash - expense_total,
            unknown=unknown,
        )

    @app.post("/despesas")
    @authenticated
    def expense_add():
        try:
            amount = cents(request.form["amount"])
            date = (
                datetime.strptime(request.form["date"], "%Y-%m-%d").date().isoformat()
            )
            description = request.form.get("description", "").strip()
            if not description or len(description) > 180:
                raise ValueError()
            db().execute(
                "INSERT INTO expenses(owner,description,amount,date) VALUES(?,?,?,?)",
                (g.user["id"], description, amount, date),
            )
            db().commit()
            flash("Despesa registrada.", "success")
        except (ValueError, KeyError):
            flash("Confira descrição, valor e data.", "error")
        return redirect(url_for("finance"))

    @app.post("/despesas/<int:eid>/excluir")
    @authenticated
    def expense_delete(eid):
        owned("expenses", eid)
        db().execute("DELETE FROM expenses WHERE id=?", (eid,))
        db().commit()
        return redirect(url_for("finance"))

    @app.post("/sessoes/<int:aid>/recebimento")
    @authenticated
    def payment_date(aid):
        row = owned("appointments", aid)
        if not row["paid"] or row["payment_id"]:
            abort(400)
        try:
            date = (
                datetime.strptime(request.form["paid_at"], "%Y-%m-%d")
                .date()
                .isoformat()
            )
        except (ValueError, KeyError):
            abort(400)
        if date > datetime.now().date().isoformat():
            abort(400)
        db().execute("UPDATE appointments SET paid_at=? WHERE id=?", (date, aid))
        db().commit()
        return redirect(url_for("finance"))

    @app.route("/disponibilidade", methods=["GET", "POST"])
    @authenticated
    def availability():
        if request.method == "POST":
            try:
                start = datetime.strptime(request.form["start"], "%H:%M").strftime(
                    "%H:%M"
                )
                end = datetime.strptime(request.form["end"], "%H:%M").strftime("%H:%M")
                days = sorted(set(int(d) for d in request.form.getlist("days")))
                if start >= end or not days or any(d < 0 or d > 6 for d in days):
                    raise ValueError()
                db().execute(
                    "UPDATE users SET workdays=?,work_start=?,work_end=? WHERE id=?",
                    (",".join(map(str, days)), start, end, g.user["id"]),
                )
                db().commit()
                flash("Disponibilidade atualizada.", "success")
                return redirect(url_for("metrics"))
            except (ValueError, KeyError):
                flash("Confira os dias e horários de trabalho.", "error")
        return render_template("availability.html", page="Disponibilidade")

    @app.get("/indicadores")
    @authenticated
    def metrics():
        month = request.args.get("month", datetime.now().strftime("%Y-%m"))
        try:
            if datetime.strptime(month, "%Y-%m").strftime("%Y-%m") != month:
                raise ValueError()
        except ValueError:
            abort(400)
        data = [
            r
            for r in rows()
            if r["start"].startswith(month) and r["status"] != "Cancelada"
        ]
        past = [r for r in data if datetime.fromisoformat(r["start"]) < datetime.now()]
        decided = [r for r in past if r["status"] in ("Realizada", "Faltou")]
        missed = sum(1 for r in decided if r["status"] == "Faltou")
        overdue = sum(r["amount"] for r in past if not r["paid"])
        hours = sum(r["duration"] for r in data) / 60
        year, number = map(int, month.split("-"))
        capacity = booked = 0
        for day in range(1, calendar.monthrange(year, number)[1] + 1):
            date = datetime(year, number, day)
            if str(date.weekday()) not in g.user["workdays"].split(","):
                continue
            begin = datetime.fromisoformat(
                date.date().isoformat() + "T" + g.user["work_start"]
            )
            end = datetime.fromisoformat(
                date.date().isoformat() + "T" + g.user["work_end"]
            )
            capacity += (end - begin).total_seconds() / 60
            for row in data:
                start = datetime.fromisoformat(row["start"])
                finish = start + timedelta(minutes=row["duration"])
                booked += max(
                    0, (min(end, finish) - max(begin, start)).total_seconds() / 60
                )
        occupancy = round(booked / capacity * 100, 1) if capacity else 0
        return render_template(
            "metrics.html",
            page="Indicadores",
            month=month,
            missed=missed,
            rate=round(100 * missed / len(decided), 1) if decided else 0,
            overdue=overdue,
            hours=round(hours, 1),
            total=len(data),
            occupancy=occupancy,
            capacity=round(capacity / 60, 1),
        )

    register_payments(app, db, authenticated, owned, payment_ready, public_base)
    register_jobs(app, db, confirmation_link)
    register_security(app, db, authenticated)


def register_payments(app, db, authenticated, owned, payment_ready, public_base):
    def reconcile(payment):
        db().execute("BEGIN IMMEDIATE")
        reference = payment.get("external_reference", "").split(":")
        if len(reference) != 4 or reference[0] != "psi":
            raise ValueError("Referência inválida.")
        row = (
            db()
            .execute(
                "SELECT * FROM appointments WHERE id=? AND owner=? AND payment_key=?",
                (reference[2], reference[1], reference[3]),
            )
            .fetchone()
        )
        merchant = (
            db()
            .execute("SELECT email FROM users WHERE id=?", (reference[1],))
            .fetchone()
        )
        if (
            not row
            or not merchant
            or merchant["email"] != app.config.get("MP_OWNER_EMAIL")
        ):
            raise ValueError("Conta inválida.")
        if (
            payment.get("currency_id") != "BRL"
            or Decimal(str(payment.get("transaction_amount", 0)))
            != Decimal(row["amount"]) / 100
        ):
            raise ValueError("Valor divergente.")
        payment_id = str(payment["id"])
        if row["payment_id"] and row["payment_id"] != payment_id:
            raise ValueError("Cobrança divergente.")
        status = payment.get("status")
        paid = row["paid"]
        paid_at = row["paid_at"]
        if status == "approved":
            if row["status"] == "Cancelada":
                raise ValueError("Sessão cancelada.")
            paid = 1
            paid_at = (
                datetime.fromisoformat(payment["date_approved"].replace("Z", "+00:00"))
                .date()
                .isoformat()
            )
        elif status in ("refunded", "charged_back", "cancelled", "rejected"):
            paid = 0
            paid_at = None
        db().execute(
            "UPDATE appointments SET payment_id=?,paid=?,paid_at=? WHERE id=?",
            (payment_id, paid, paid_at, row["id"]),
        )
        db().commit()
        return status

    @app.route("/sessoes/<int:aid>/pix", methods=["GET", "POST"])
    @authenticated
    def pix(aid):
        row = owned("appointments", aid)
        if not payment_ready():
            flash(
                "Configure a conta Mercado Pago e o webhook para habilitar Pix.",
                "error",
            )
            return redirect(url_for("finance"))
        if (
            row["status"] == "Cancelada"
            or (row["paid"] and not row["payment_id"])
            or row["amount"] <= 0
        ):
            abort(400)
        patient = owned("patients", row["patient"])
        if not patient["email"]:
            flash("Cadastre o e-mail do paciente para emitir o Pix.", "error")
            return redirect(url_for("patient_edit", pid=patient["id"]))
        payment = None
        try:
            if request.method == "POST":
                # Lock only local state; network request uses the persisted idempotency key.
                db().execute("BEGIN IMMEDIATE")
                row = owned("appointments", aid)
                if (
                    row["status"] == "Cancelada"
                    or (row["paid"] and not row["payment_id"])
                    or row["amount"] <= 0
                ):
                    abort(400)
                if not row["payment_key"]:
                    db().execute(
                        "UPDATE appointments SET payment_key=? WHERE id=?",
                        (secrets.token_urlsafe(24), aid),
                    )
                db().commit()
                row = owned("appointments", aid)
                payment = (
                    integrations.pix_fetch(app.config, row["payment_id"])
                    if row["payment_id"]
                    else integrations.pix_request(app.config, row, patient["email"])
                )
                reconcile(payment)
                if request.form.get("action") == "close" and payment.get("status") in (
                    "cancelled",
                    "refunded",
                    "rejected",
                    "charged_back",
                ):
                    db().execute(
                        "UPDATE appointments SET payment_id=NULL,payment_key=NULL WHERE id=?",
                        (aid,),
                    )
                    db().commit()
                    flash("Cobrança conciliada e desvinculada.", "success")
                    return redirect(url_for("finance"))
            elif row["payment_id"]:
                payment = integrations.pix_fetch(app.config, row["payment_id"])
            code = (
                (payment or {})
                .get("point_of_interaction", {})
                .get("transaction_data", {})
                .get("qr_code", "")
            )
        except (URLError, ValueError, KeyError, TypeError):
            db().rollback()
            flash(
                "Não foi possível consultar o Pix. Tente novamente; a chave de cobrança evita emissão duplicada.",
                "error",
            )
            code = ""
        return render_template(
            "pix.html",
            page="Cobrança Pix",
            a=owned("appointments", aid),
            code=code,
            payment=payment,
        )

    @app.post("/webhooks/mercadopago")
    def mp_webhook():
        secret = app.config.get("MP_WEBHOOK_SECRET")
        if not secret or not app.config.get("MP_ACCESS_TOKEN"):
            abort(503)
        parts = {}
        for item in request.headers.get("x-signature", "").split(","):
            key, sep, value = item.strip().partition("=")
            if sep:
                parts[key] = value
        data_id = request.args.get("data.id", "").lower()
        request_id = request.headers.get("x-request-id", "")
        timestamp = parts.get("ts", "")
        try:
            seconds = int(timestamp)
            if seconds > 10**12:
                seconds //= 1000
            if abs(int(datetime.now().timestamp()) - seconds) > 300:
                abort(401)
        except ValueError:
            abort(401)
        manifest = f"id:{data_id};request-id:{request_id};ts:{timestamp};"
        signature = hmac.new(
            secret.encode(), manifest.encode(), hashlib.sha256
        ).hexdigest()
        if (
            not data_id.isdigit()
            or not request_id
            or not hmac.compare_digest(signature, parts.get("v1", ""))
        ):
            abort(401)
        try:
            payment = integrations.pix_fetch(app.config, data_id)
            if str(payment.get("id")) != data_id:
                abort(400)
            reconcile(payment)
        except (URLError, ValueError, KeyError, TypeError):
            abort(400)
        return {"ok": True}


def register_jobs(app, db, confirmation_link):
    @app.cli.command("send-reminders")
    def send_reminders():
        """Run every 5 minutes with cron; recipients must opt in."""
        now = datetime.now()
        appointments = (
            db()
            .execute(
                "SELECT a.*,p.phone,p.email,p.reminder_consent FROM appointments a JOIN patients p ON p.id=a.patient WHERE a.status IN ('Agendada','Confirmada') AND a.start>? AND a.start<=? AND p.reminder_consent=1",
                (
                    now.isoformat(timespec="minutes"),
                    (now + timedelta(hours=24)).isoformat(timespec="minutes"),
                ),
            )
            .fetchall()
        )
        sent = failed = 0
        for row in appointments:
            channel = (
                "whatsapp"
                if app.config.get("WA_ACCESS_TOKEN")
                and app.config.get("WA_TEMPLATE")
                and row["phone"]
                else "email"
            )
            if channel == "email" and (
                not row["email"] or not app.config.get("SMTP_HOST")
            ):
                continue
            try:
                link = confirmation_link(row)
            except ValueError as error:
                raise click.ClickException(str(error))
            db().execute("BEGIN IMMEDIATE")
            current = (
                db()
                .execute(
                    "SELECT a.id FROM appointments a JOIN patients p ON p.id=a.patient WHERE a.id=? AND a.start=? AND a.confirmation_nonce=? AND a.status IN ('Agendada','Confirmada') AND p.reminder_consent=1",
                    (row["id"], row["start"], row["confirmation_nonce"]),
                )
                .fetchone()
            )
            if not current:
                db().rollback()
                continue
            result = db().execute(
                "INSERT OR IGNORE INTO deliveries VALUES(?,?,?,'Enviando')",
                (row["id"], row["start"], channel),
            )
            db().commit()
            if not result.rowcount:
                continue
            try:
                label = app.jinja_env.filters["datebr"](row["start"])
                if channel == "whatsapp":
                    integrations.send_whatsapp(app.config, row["phone"], label, link)
                else:
                    integrations.send_mail(
                        app.config,
                        row["email"],
                        "Lembrete de horário",
                        f"Seu horário: {label}. Confirme sua presença: {link}",
                    )
                status = "Enviado"
                sent += 1
            except (URLError, RuntimeError, OSError, ValueError):
                status = "Falhou"
                failed += 1
            db().execute(
                "UPDATE deliveries SET status=? WHERE appointment=? AND start=? AND channel=?",
                (status, row["id"], row["start"], channel),
            )
            db().commit()
        click.echo(
            f"Enviados: {sent}. Falhas: {failed}. Use reminder-status para conferir; nenhum reenvio automático em resultado incerto."
        )

    @app.cli.command("reminder-status")
    def reminder_status():
        for row in db().execute(
            "SELECT appointment,start,channel,status FROM deliveries ORDER BY start DESC LIMIT 100"
        ):
            click.echo(
                f"{row['appointment']} | {row['start']} | {row['channel']} | {row['status']}"
            )

    @app.cli.command("retry-reminder")
    @click.argument("appointment", type=int)
    @click.confirmation_option(
        prompt="Você conferiu no provedor que a mensagem não foi enviada?"
    )
    def retry_reminder(appointment):
        db().execute(
            "DELETE FROM deliveries WHERE appointment=? AND status IN ('Falhou','Enviando')",
            (appointment,),
        )
        db().commit()
        click.echo(
            "Reenvio liberado para a próxima execução de send-reminders, se ainda elegível."
        )
