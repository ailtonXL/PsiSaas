"""External adapters. Secrets stay on the server; no patient data is logged."""

import json
import smtplib
import ssl
from email.message import EmailMessage
from urllib.request import Request, urlopen


def send_mail(config, recipient, subject, text):
    if not config.get("SMTP_HOST") or not config.get("MAIL_FROM"):
        raise RuntimeError("Configure SMTP_HOST e MAIL_FROM para enviar e-mails.")
    msg = EmailMessage()
    msg["From"] = config["MAIL_FROM"]
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(text)
    with smtplib.SMTP(
        config["SMTP_HOST"], int(config.get("SMTP_PORT") or 587), timeout=20
    ) as server:
        server.starttls(context=ssl.create_default_context())
        if config.get("SMTP_USER"):
            server.login(config["SMTP_USER"], config.get("SMTP_PASSWORD", ""))
        server.send_message(msg)


def api_json(url, token, payload=None, extra_headers=None):
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        **(extra_headers or {}),
    }
    req = Request(
        url,
        headers=headers,
        data=json.dumps(payload).encode() if payload is not None else None,
    )
    with urlopen(req, timeout=20) as response:
        return json.load(response)


def pix_request(config, row, email):
    return api_json(
        "https://api.mercadopago.com/v1/payments",
        config["MP_ACCESS_TOKEN"],
        {
            "transaction_amount": row["amount"] / 100,
            "description": "Agendamento",
            "payment_method_id": "pix",
            "payer": {"email": email},
            "external_reference": f"psi:{row['owner']}:{row['id']}:{row['payment_key']}",
            "notification_url": config["PUBLIC_BASE_URL"].rstrip("/")
            + "/webhooks/mercadopago",
        },
        {"X-Idempotency-Key": row["payment_key"]},
    )


def pix_fetch(config, payment_id):
    if not str(payment_id).isdigit():
        raise ValueError("Pagamento inválido.")
    return api_json(
        "https://api.mercadopago.com/v1/payments/" + str(payment_id),
        config["MP_ACCESS_TOKEN"],
    )


def send_whatsapp(config, phone, date_label, confirmation_url):
    # The approved template must have three body parameters: name-free greeting,
    # date/time and confirmation URL. First parameter is a neutral service label.
    phone = phone if phone.startswith("55") and len(phone) >= 12 else "55" + phone
    sender = config.get("WA_PHONE_ID", "")
    if not sender.isdigit():
        raise RuntimeError("Configure WA_PHONE_ID.")
    return api_json(
        "https://graph.facebook.com/v22.0/" + sender + "/messages",
        config["WA_ACCESS_TOKEN"],
        {
            "messaging_product": "whatsapp",
            "to": phone,
            "type": "template",
            "template": {
                "name": config["WA_TEMPLATE"],
                "language": {"code": "pt_BR"},
                "components": [
                    {
                        "type": "body",
                        "parameters": [
                            {"type": "text", "text": x}
                            for x in ["seu agendamento", date_label, confirmation_url]
                        ],
                    }
                ],
            },
        },
    )
