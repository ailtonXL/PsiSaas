import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.error import URLError
from cryptography.fernet import Fernet
import test_app
from app import create_app
from security import totp


class ImprovementsTest(test_app.TestSupport):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            PUBLIC_BASE_URL="https://psi.example.com",
            MFA_KEY=Fernet.generate_key().decode(),
            BACKUP_KEY=Fernet.generate_key().decode(),
            SMTP_HOST="smtp.example.com",
            MAIL_FROM="psi@example.com",
        )
        self.future = (datetime.now() + timedelta(days=10)).replace(
            hour=10, minute=0, second=0, microsecond=0
        )

    def query(self, sql, args=()):
        with sqlite3.connect(self.app.config["DATABASE"]) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, args).fetchall()
            conn.commit()
            return rows

    def book(self, **kwargs):
        return super().book(
            **{"start": self.future.isoformat(timespec="minutes"), **kwargs}
        )

    def edit(self, **kwargs):
        return self.post(
            "/sessoes/1/editar",
            {
                "patient": "1",
                "start": (self.future + timedelta(hours=1)).isoformat(
                    timespec="minutes"
                ),
                "duration": "60",
                "amount": "200",
                "mode": "Online",
                **kwargs,
            },
        )

    def token_path(self, html, kind):
        match = re.search(r"https://psi.example.com(/" + kind + r"/[^<]+)", html)
        self.assertIsNotNone(match, html)
        return match[1]

    def test_recurring_atomic_edit_and_rollback(self):
        self.patient()
        self.book(repeat="4")
        original = self.query("SELECT * FROM appointments")
        self.assertEqual(len(original), 4)
        self.assertEqual(len({r["series_id"] for r in original}), 1)
        self.assertIn("4 sessão", self.edit(scope="series").text)
        changed = self.query("SELECT * FROM appointments ORDER BY start")
        self.assertTrue(
            all(r["duration"] == 60 and r["amount"] == 20000 for r in changed)
        )
        self.assertNotEqual(
            original[0]["confirmation_nonce"], changed[0]["confirmation_nonce"]
        )
        self.book(
            start=(self.future + timedelta(weeks=2, hours=2)).isoformat(
                timespec="minutes"
            )
        )
        before = [dict(r) for r in self.query("SELECT * FROM appointments")]
        result = self.edit(
            scope="series",
            start=(self.future + timedelta(hours=2)).isoformat(timespec="minutes"),
        )
        self.assertIn("Já existe", result.text)
        self.assertEqual(
            before, [dict(r) for r in self.query("SELECT * FROM appointments")]
        )

    def test_recurrence_creation_rollback(self):
        self.patient()
        self.book(
            start=(self.future + timedelta(weeks=2)).isoformat(timespec="minutes")
        )
        self.assertIn("Já existe", self.book(repeat="4").text)
        self.assertEqual(len(self.query("SELECT * FROM appointments")), 1)
        self.assertIn("Confira", self.book(repeat="53").text)

    def test_public_confirmation_and_invalidation(self):
        self.patient()
        self.book()
        path = self.token_path(
            self.client.get("/sessoes/1/confirmacao").text, "confirmar"
        )
        public = self.app.test_client()
        self.assertEqual(public.get(path).status_code, 200)
        self.assertEqual(self.post(path, client=public).status_code, 200)
        self.assertEqual(
            self.query("SELECT status FROM appointments")[0][0], "Confirmada"
        )
        self.edit()
        self.assertEqual(public.get(path).status_code, 410)
        self.assertEqual(public.get(path + "tampered").status_code, 410)

    def test_waitlist_first_acceptance_wins(self):
        self.patient()
        self.book()
        self.post("/sessoes/1/atualizar", {"action": "Cancelada"})
        self.post("/pacientes/1/espera")
        first = self.token_path(
            self.post("/sessoes/1/ofertas", {"patient": "1"}).text, "vaga"
        )
        second = self.token_path(
            self.post("/sessoes/1/ofertas", {"patient": "1"}).text, "vaga"
        )
        public = self.app.test_client()
        public.get(first)
        self.assertIn("Horário reservado", self.post(first, client=public).text)
        self.assertEqual(public.get(second).status_code, 410)
        self.assertEqual(self.query("SELECT COUNT(*) FROM appointments")[0][0], 2)
        self.assertEqual(self.query("SELECT waiting FROM patients")[0][0], 0)
        self.assertIn(
            "Já existe", self.post("/sessoes/1/atualizar", {"action": "Agendada"}).text
        )

    def test_edit_export_delete_and_tenant_controls(self):
        self.patient()
        self.book()
        self.assertIn(
            "Paciente atualizado",
            self.post(
                "/pacientes/1/editar",
                {
                    "name": "Maria Atualizada",
                    "email": "maria@example.com",
                    "phone": "11988887777",
                    "consent": "on",
                },
            ).text,
        )
        export = self.client.get("/pacientes/1/exportar").json
        self.assertEqual(export["paciente"]["name"], "Maria Atualizada")
        self.assertEqual(len(export["sessoes"]), 1)
        other = self.app.test_client()
        self.login("two@example.com", other)
        for path in [
            "/pacientes/1/editar",
            "/pacientes/1/exportar",
            "/sessoes/1/editar",
            "/sessoes/1/confirmacao",
            "/sessoes/1/ofertas",
            "/sessoes/1/pix",
        ]:
            self.assertEqual(other.get(path).status_code, 404, path)
        self.assertEqual(
            self.post(
                "/pacientes/1/excluir", {"confirm": "EXCLUIR"}, other
            ).status_code,
            404,
        )
        self.assertEqual(
            self.post("/pacientes/1/excluir", {"confirm": "wrong"}).status_code, 400
        )
        self.post("/pacientes/1/excluir", {"confirm": "EXCLUIR"})
        self.assertEqual(len(self.query("SELECT * FROM appointments")), 0)
        self.assertEqual(len(self.query("SELECT * FROM patients")), 0)

    def test_cash_expenses_and_metrics(self):
        self.patient()
        self.book()
        day = datetime.now().date().isoformat()
        month = day[:7]
        self.post("/sessoes/1/atualizar", {"action": "paid", "paid_at": day})
        self.post(
            "/despesas", {"description": "Aluguel", "amount": "80.50", "date": day}
        )
        page = self.client.get("/financeiro?month=" + month).text
        self.assertIn("R$ 100,00", page)
        self.assertIn("Aluguel", page)
        self.assertEqual(self.query("SELECT paid_at FROM appointments")[0][0], day)
        other = self.app.test_client()
        self.login("two@example.com", other)
        self.assertEqual(
            self.post("/despesas/1/excluir", client=other).status_code, 404
        )
        self.assertNotIn("Aluguel", other.get("/financeiro").text)
        self.post(
            "/disponibilidade",
            {"days": ["0", "1", "2", "3", "4"], "start": "08:00", "end": "18:00"},
        )
        self.assertEqual(self.client.get("/indicadores").status_code, 200)
        self.assertEqual(self.client.get("/disponibilidade").status_code, 200)
        self.assertEqual(self.client.get("/financeiro?month=bad").status_code, 400)

    def test_reminders_consent_and_deduplication(self):
        self.patient()
        self.query(
            "UPDATE patients SET email=?,reminder_consent=1 WHERE id=1",
            ("maria@example.com",),
        )
        self.book(
            start=(datetime.now() + timedelta(hours=3)).isoformat(timespec="minutes")
        )
        runner = self.app.test_cli_runner()
        with patch("integrations.send_mail") as send:
            result = runner.invoke(args=["send-reminders"])
            self.assertEqual(result.exit_code, 0, str(result.exception))
            self.assertEqual(send.call_count, 1)
            self.assertIn("/confirmar/", send.call_args.args[3])
            runner.invoke(args=["send-reminders"])
            self.assertEqual(send.call_count, 1)
        self.assertEqual(self.query("SELECT status FROM deliveries")[0][0], "Enviado")
        self.query("UPDATE patients SET reminder_consent=0")
        self.query("DELETE FROM deliveries")
        with patch("integrations.send_mail") as send:
            runner.invoke(args=["send-reminders"])
            send.assert_not_called()

    def test_reset_single_use_and_session_invalidation(self):
        existing = self.app.test_client()
        self.login("one@example.com", existing)
        self.post("/logout")
        with patch("integrations.send_mail") as send:
            self.post("/recuperar", {"email": "one@example.com"})
            link = re.search(
                r"https://psi.example.com(/redefinir/\S+)", send.call_args.args[3]
            )[1]
        self.assertEqual(self.client.get(link).status_code, 200)
        self.post(
            link, {"password": "a-new-long-password", "confirm": "a-new-long-password"}
        )
        self.assertEqual(self.client.get(link).status_code, 410)
        self.assertEqual(existing.get("/pacientes").status_code, 302)
        result = self.post(
            "/login", {"email": "one@example.com", "password": "a-new-long-password"}
        )
        self.assertIn("Olá", result.text)

    def test_totp_setup_login_and_replay(self):
        self.post("/conta", {"action": "prepare", "password": "long-test-password"})
        with self.client.session_transaction() as session:
            secret = session["totp_pending"]
        step = int(time.time()) // 30
        self.post(
            "/conta",
            {
                "action": "enable",
                "password": "long-test-password",
                "code": totp(secret, step),
            },
        )
        self.assertNotIn(
            secret, self.query("SELECT totp_secret FROM users WHERE id=1")[0][0]
        )
        self.assertEqual(
            self.post(
                "/conta", {"action": "prepare", "password": "long-test-password"}
            ).status_code,
            400,
        )
        self.post("/logout")
        self.login("one@example.com")
        self.assertEqual(self.client.get("/").status_code, 302)
        result = self.post("/login/codigo", {"code": totp(secret, step)})
        self.assertIn("já utilizado", result.text)
        self.post("/login/codigo", {"code": totp(secret, step + 1)})
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_backup_restore_roundtrip(self):
        self.patient()
        self.book()
        backup = os.path.join(self.tmp.name, "backup.enc")
        restored = os.path.join(self.tmp.name, "restored.db")
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["backup", backup])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn(b"Maria", Path(backup).read_bytes())
        result = runner.invoke(args=["restore-backup", backup, restored])
        self.assertEqual(result.exit_code, 0, result.output)
        with sqlite3.connect(restored) as conn:
            self.assertEqual(
                conn.execute("SELECT name FROM patients").fetchone()[0], "Maria"
            )
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.app.config["BACKUP_KEY"] = Fernet.generate_key().decode()
        failed = runner.invoke(args=["restore-backup", backup, restored + ".wrong"])
        self.assertNotEqual(failed.exit_code, 0)
        self.assertFalse(os.path.exists(restored + ".wrong"))

    def pix_setup(self):
        self.app.config.update(
            MP_ACCESS_TOKEN="fake-test-token",
            MP_WEBHOOK_SECRET="fake-test-secret",
            MP_OWNER_EMAIL="one@example.com",
        )
        self.patient()
        self.query("UPDATE patients SET email=? WHERE id=1", ("maria@example.com",))
        self.book()

    def payment(self, status="pending"):
        row = self.query("SELECT * FROM appointments WHERE id=1")[0]
        return {
            "id": 123,
            "status": status,
            "currency_id": "BRL",
            "transaction_amount": 180.5,
            "external_reference": f"psi:1:1:{row['payment_key']}",
            "date_approved": "2026-11-11T10:00:00-03:00",
            "point_of_interaction": {"transaction_data": {"qr_code": "pix-test-code"}},
        }

    def webhook(self):
        ts = str(int(time.time()))
        manifest = f"id:123;request-id:test-request;ts:{ts};"
        signature = hmac.new(
            b"fake-test-secret", manifest.encode(), hashlib.sha256
        ).hexdigest()
        return self.client.post(
            "/webhooks/mercadopago?data.id=123",
            headers={
                "x-request-id": "test-request",
                "x-signature": f"ts={ts},v1={signature}",
            },
            json={"type": "payment"},
        )

    def test_pix_verified_webhook_idempotent_and_refund(self):
        self.pix_setup()
        with patch("integrations.pix_request", side_effect=lambda *a: self.payment()):
            self.assertIn("pix-test-code", self.post("/sessoes/1/pix").text)
        self.assertEqual(
            self.client.post("/webhooks/mercadopago?data.id=123", json={}).status_code,
            401,
        )
        self.assertEqual(self.query("SELECT paid FROM appointments")[0][0], 0)
        with patch("integrations.pix_fetch", return_value=self.payment("approved")):
            self.assertEqual(self.webhook().status_code, 200)
            self.assertEqual(self.webhook().status_code, 200)
        self.assertEqual(self.query("SELECT paid FROM appointments")[0][0], 1)
        self.assertIn(
            "provedor", self.post("/sessoes/1/atualizar", {"action": "paid"}).text
        )
        with patch("integrations.pix_fetch", return_value=self.payment("refunded")):
            self.assertEqual(self.webhook().status_code, 200)
            self.post("/sessoes/1/pix", {"action": "close"})
        row = self.query("SELECT * FROM appointments")[0]
        self.assertFalse(row["paid"])
        self.assertIsNone(row["payment_key"])

    def test_pix_wrong_amount_and_other_tenant(self):
        self.pix_setup()
        with patch("integrations.pix_request", side_effect=lambda *a: self.payment()):
            self.post("/sessoes/1/pix")
        payment = self.payment("approved")
        payment["transaction_amount"] = 1
        with patch("integrations.pix_fetch", return_value=payment):
            self.assertEqual(self.webhook().status_code, 400)
        self.assertEqual(self.query("SELECT paid FROM appointments")[0][0], 0)
        other = self.app.test_client()
        self.login("two@example.com", other)
        self.assertEqual(self.post("/sessoes/1/pix", client=other).status_code, 404)

    def test_legacy_database_migration_preserves_rows(self):
        path = os.path.join(self.tmp.name, "legacy.db")
        with sqlite3.connect(path) as conn:
            conn.executescript(
                "CREATE TABLE users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,name TEXT,password TEXT); CREATE TABLE patients(id INTEGER PRIMARY KEY,owner INTEGER,name TEXT,phone TEXT,email TEXT,waiting INTEGER); CREATE TABLE appointments(id INTEGER PRIMARY KEY,owner INTEGER,patient INTEGER,start TEXT,duration INTEGER,amount INTEGER,mode TEXT,status TEXT,paid INTEGER); INSERT INTO users VALUES(1,'legacy@example.com','Legacy','hash'); INSERT INTO patients VALUES(1,1,'Paciente','','',0); INSERT INTO appointments VALUES(1,1,1,'2026-01-01T10:00',50,10000,'Online','Realizada',1);"
            )
        config = {
            "TESTING": True,
            "SECRET_KEY": "long-migration-key" * 3,
            "DATABASE": path,
        }
        create_app(config)
        create_app(config)
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                "SELECT amount,paid,paid_at,confirmation_nonce FROM appointments"
            ).fetchone()
            self.assertEqual(row[:3], (10000, 1, None))
            self.assertTrue(row[3])

    def test_concurrent_waitlist_acceptance(self):
        self.patient()
        self.book()
        self.post("/sessoes/1/atualizar", {"action": "Cancelada"})
        self.post("/pacientes/1/espera")
        paths = [
            self.token_path(
                self.post("/sessoes/1/ofertas", {"patient": "1"}).text, "vaga"
            )
            for _ in range(2)
        ]

        def accept(path):
            client = self.app.test_client()
            client.get(path)
            return self.post(path, client=client).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(accept, paths))
        self.assertEqual(sorted(statuses), [200, 410])
        self.assertEqual(
            self.query("SELECT COUNT(*) FROM appointments WHERE status!='Cancelada'")[
                0
            ][0],
            1,
        )

    def test_failed_reminder_requires_review_before_retry(self):
        self.patient()
        self.query(
            "UPDATE patients SET email=?,reminder_consent=1 WHERE id=1",
            ("maria@example.com",),
        )
        self.book(
            start=(datetime.now() + timedelta(hours=2)).isoformat(timespec="minutes")
        )
        runner = self.app.test_cli_runner()
        with patch("integrations.send_mail", side_effect=OSError("timeout")) as send:
            result = runner.invoke(args=["send-reminders"])
            self.assertEqual(result.exit_code, 0, str(result.exception))
            runner.invoke(args=["send-reminders"])
            self.assertEqual(send.call_count, 1)
        self.assertEqual(self.query("SELECT status FROM deliveries")[0][0], "Falhou")
        runner.invoke(args=["retry-reminder", "1", "--yes"])
        with patch("integrations.send_mail") as send:
            runner.invoke(args=["send-reminders"])
            self.assertEqual(send.call_count, 1)

    def test_pix_timeout_reuses_key_and_blocks_manual_changes(self):
        self.pix_setup()
        with patch("integrations.pix_request", side_effect=URLError("timeout")):
            self.post("/sessoes/1/pix")
        key = self.query("SELECT payment_key FROM appointments")[0][0]
        self.assertTrue(key)
        self.assertIn(
            "provedor", self.post("/sessoes/1/atualizar", {"action": "paid"}).text
        )
        self.assertIn("cobrança Pix", self.edit().text)
        with patch("integrations.pix_request", side_effect=lambda *a: self.payment()):
            self.post("/sessoes/1/pix")
        self.assertEqual(key, self.query("SELECT payment_key FROM appointments")[0][0])
