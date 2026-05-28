"""
email_engine.py
SendGrid-based delivery with tracking
"""

import os
import hmac
import hashlib
import uuid
import logging
from datetime import datetime, timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content, ReplyTo
from models import db, CampaignSend, Target, Campaign

logger = logging.getLogger(__name__)

sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")

# M-4: Warn at import time if BASE_URL is not HTTPS in production
if os.getenv("FLASK_ENV") == "production" and not BASE_URL.startswith("https://"):
    logger.warning(
        "BASE_URL is set to a non-HTTPS value (%s) in a production environment. "
        "All tracking links will use unencrypted HTTP. Set BASE_URL to an https:// URL.",
        BASE_URL
    )

# HMAC key for signing send_ids (H-5)
# Must match the key used in app.py — both read from SEND_ID_HMAC_SECRET (falling back to FLASK_SECRET_KEY)
_FLASK_SECRET = os.getenv("FLASK_SECRET_KEY", "")
_HMAC_SECRET = os.getenv("SEND_ID_HMAC_SECRET", _FLASK_SECRET).encode()


def _sign_send_id(raw_id: str) -> str:
    """Return '<uuid>.<hmac>' — the signed send_id stored in the DB and embedded in URLs."""
    sig = hmac.new(_HMAC_SECRET, raw_id.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{raw_id}.{sig}"


def send_phishing_email(
    campaign: Campaign,
    target: Target,
    email_data: dict
) -> str:
    """Send one phishing email with unique tracking and store the record."""

    raw_id = uuid.uuid4().hex           # Random UUID (32 hex chars)
    send_id = _sign_send_id(raw_id)     # H-5: HMAC-signed send_id

    tracking_link = f"{BASE_URL}/c/{send_id}"
    report_link = f"{BASE_URL}/r/{send_id}"
    open_pixel = f'<img src="{BASE_URL}/o/{send_id}" width="1" height="1" style="display:none" />'

    body_html = email_data["body_html"]
    body_html = body_html.replace("[TRACKING_LINK]", tracking_link)
    body_html = body_html.replace("[REPORT_LINK]", report_link)
    body_html += open_pixel

    message = Mail(
        from_email=Email(email_data["sender_email"], email_data["sender_name"]),
        to_emails=To(target.email, f"{target.first_name} {target.last_name}"),
        subject=email_data["subject"],
        html_content=Content("text/html", body_html)
    )

    if email_data.get("reply_to"):
        message.reply_to = ReplyTo(email_data["reply_to"])

    try:
        sg.send(message)

        send_record = CampaignSend(
            id=send_id,
            campaign_id=campaign.id,
            target_id=target.id,
            email_subject=email_data["subject"],
            email_body=body_html,
            sender_email=email_data["sender_email"],
            sender_name=email_data["sender_name"],
            sent_at=datetime.now(timezone.utc)  # L-1
        )
        db.session.add(send_record)
        db.session.commit()

        return send_id
    except Exception as e:
        # M-3: Structured logging — do NOT log the raw email address or full exception message
        email_hash = hashlib.sha256(target.email.encode()).hexdigest()[:8]
        logger.error(
            "Failed to send email to target_hash=%s campaign_id=%s error_type=%s",
            email_hash,
            campaign.id,
            type(e).__name__
        )
        return None


def send_manager_summary(to_email: str, subject: str, html_body: str):
    """Send the post-campaign summary to the IT manager."""
    message = Mail(
        from_email=Email(os.getenv("SENDGRID_FROM_EMAIL"), "Phishing Sim Platform"),
        to_emails=To(to_email),
        subject=subject,
        html_content=Content("text/html", html_body)
    )
    try:
        sg.send(message)
    except Exception as e:
        logger.error("Failed to send manager summary: error_type=%s", type(e).__name__)
