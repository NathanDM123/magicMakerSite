import os
import ssl
import smtplib
from email.message import EmailMessage


def send_verification_email(to_email: str, code: str):
    EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise RuntimeError("EMAIL_ADDRESS ou EMAIL_PASSWORD non configuré dans le .env")

    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "465"))
    smtp_use_ssl = os.environ.get("SMTP_USE_SSL", "1").lower() in ("1", "true", "yes")

    if not smtp_host:
        raise RuntimeError(
            "SMTP_HOST manquant"
        )

    msg = EmailMessage()
    msg["Subject"] = "Votre code de vérification"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg.set_content(f"Votre code de vérification est : {code}")

    if smtp_use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)