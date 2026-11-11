"""Validated scheduling operations shared by authenticated and public flows."""

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import secrets


def cents(value):
    try:
        number = Decimal(str(value).replace(",", "."))
        if (
            not number.is_finite()
            or number < 0
            or number > 100000
            or number.as_tuple().exponent < -2
        ):
            raise ValueError()
        return int(number * 100)
    except (InvalidOperation, TypeError):
        raise ValueError("Valor inválido.")


def appointment_input(form):
    start = datetime.fromisoformat(form["start"])
    duration = int(form["duration"])
    mode = form["mode"]
    if (
        start.tzinfo
        or start.second
        or start.microsecond
        or duration not in (30, 45, 50, 60, 90)
        or mode not in ("Presencial", "Online")
    ):
        raise ValueError("Dados da sessão inválidos.")
    return start, duration, cents(form["amount"]), mode


def check_conflicts(db, owner, proposed, excluded=()):
    existing = db.execute(
        "SELECT id,start,duration FROM appointments WHERE owner=? AND status!='Cancelada'",
        (owner,),
    ).fetchall()
    intervals = [
        (datetime.fromisoformat(r["start"]), r["duration"])
        for r in existing
        if r["id"] not in excluded
    ]
    for start, duration in proposed:
        end = start + timedelta(minutes=duration)
        if any(
            start < other + timedelta(minutes=length) and end > other
            for other, length in intervals
        ):
            raise ValueError("Já existe uma sessão nesse horário.")
        intervals.append((start, duration))


def insert_appointment(db, owner, patient, start, duration, amount, mode, series=None):
    result = db.execute(
        "INSERT INTO appointments(owner,patient,start,duration,amount,mode,series_id,confirmation_nonce) VALUES(?,?,?,?,?,?,?,?)",
        (
            owner,
            patient,
            start.isoformat(timespec="minutes"),
            duration,
            amount,
            mode,
            series,
            secrets.token_urlsafe(24),
        ),
    )
    db.execute("UPDATE patients SET waiting=0 WHERE id=? AND owner=?", (patient, owner))
    return result.lastrowid


def migrate(db):
    db.execute("BEGIN IMMEDIATE")
    additions = {
        "users": {
            "totp_secret": "TEXT",
            "totp_last": "INTEGER NOT NULL DEFAULT -1",
            "session_version": "INTEGER NOT NULL DEFAULT 0",
            "workdays": "TEXT NOT NULL DEFAULT '0,1,2,3,4'",
            "work_start": "TEXT NOT NULL DEFAULT '08:00'",
            "work_end": "TEXT NOT NULL DEFAULT '18:00'",
        },
        "patients": {"reminder_consent": "INTEGER NOT NULL DEFAULT 0"},
        "appointments": {
            "series_id": "TEXT",
            "confirmation_nonce": "TEXT NOT NULL DEFAULT ''",
            "paid_at": "TEXT",
            "payment_id": "TEXT",
            "payment_key": "TEXT",
        },
    }
    for table, fields in additions.items():
        columns = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for name, declaration in fields.items():
            if name not in columns:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    for r in db.execute(
        "SELECT id FROM appointments WHERE confirmation_nonce='' "
    ).fetchall():
        db.execute(
            "UPDATE appointments SET confirmation_nonce=? WHERE id=?",
            (secrets.token_urlsafe(24), r["id"]),
        )
    # Legacy paid rows have no known settlement date: leave NULL, never invent one.
    db.executescript(
        """
    CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id), description TEXT NOT NULL, amount INTEGER NOT NULL, date TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS reset_tokens(digest TEXT PRIMARY KEY, user INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS offers(id INTEGER PRIMARY KEY, token TEXT UNIQUE NOT NULL, owner INTEGER NOT NULL REFERENCES users(id), appointment INTEGER NOT NULL REFERENCES appointments(id), patient INTEGER NOT NULL REFERENCES patients(id), expires TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Aberta');
    CREATE TABLE IF NOT EXISTS deliveries(appointment INTEGER NOT NULL REFERENCES appointments(id), start TEXT NOT NULL, channel TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(appointment,start,channel));
    CREATE INDEX IF NOT EXISTS appointments_owner_start ON appointments(owner,start);
    CREATE INDEX IF NOT EXISTS patients_owner ON patients(owner);
    """
    )
    db.commit()
