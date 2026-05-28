"""
email_engine.py
Resend-based delivery with HMAC-signed tracking links
"""

import os
import hmac
import hashlib
import uuid
import logging
from datetime import datetime, timezone
import resend
from models import db, CampaignSend, Target, Campaign

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")

# Warn at import time if BASE_URL is not HTTPS in production
if os.getenv("FLASK_ENV") == "production" and not BASE_URL.startswith("https://"):
    logger.warning(
        "BASE_URL is set to a non-HTTPS value (%s) in a production environment. "
        "All tracking links will use unencrypted HTTP. Set BASE_URL to an https:// URL.",
        BASE_URL
    )

# HMAC key for signing send_ids
# Must match the key used in app.py — both read from SEND_ID_HMAC_SECRET (falling back to FLASK_SECRET_KEY)
_FLASK_SECRET = os.getenv("FLASK_SECRET_KEY", "")
_HMAC_SECRET = os.getenv("SEND_ID_HMAC_SECRET", _FLASK_SECRET).encode()

# Resend API key — validated at startup so misconfiguration is caught early
_RESEND_API_KEY = os.getenv("RESEND_API_KEY")
if not _RESEND_API_KEY:
    logger.warning(
        "RESEND_API_KEY environment variable is not set. "
        "Email delivery will fail. Set it before sending campaigns."
    )
resend.api_key = _RESEND_API_KEY or ""

FROM_EMAIL = os.getenv("FROM_EMAIL", "noreply@example.com")


def _sign_send_id(raw_id: str) -> str:
    """Return '<uuid>.<hmac>' — the signed send_id stored in the DB and embedded in URLs."""
    sig = hmac.new(_HMAC_SECRET, raw_id.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{raw_id}.{sig}"


def send_phishing_email(
    campaign: Campaign,
    target: Target,
    email_data: dict
) -> str | None:
    """Send one phishing email with unique tracking and store the record."""

    raw_id = uuid.uuid4().hex           # Random UUID (32 hex chars)
    send_id = _sign_send_id(raw_id)     # HMAC-signed send_id

    tracking_link = f"{BASE_URL}/c/{send_id}"
    report_link = f"{BASE_URL}/r/{send_id}"
    open_pixel = f'<img src="{BASE_URL}/o/{send_id}" width="1" height="1" style="display:none" />'

    body_html = email_data["body_html"]
    body_html = body_html.replace("[TRACKING_LINK]", tracking_link)
    body_html = body_html.replace("[REPORT_LINK]", report_link)
    body_html += open_pixel

    sender = f"{email_data['sender_name']} <{email_data['sender_email']}>"

    params: resend.Emails.SendParams = {
        "from": sender,
        "to": [target.email],
        "subject": email_data["subject"],
        "html": body_html,
    }
    if email_data.get("reply_to"):
        params["reply_to"] = email_data["reply_to"]

    try:
        resend.Emails.send(params)

        send_record = CampaignSend(
            id=send_id,
            campaign_id=campaign.id,
            target_id=target.id,
            email_subject=email_data["subject"],
            email_body=body_html,
            sender_email=email_data["sender_email"],
            sender_name=email_data["sender_name"],
            sent_at=datetime.now(timezone.utc)
        )
        db.session.add(send_record)
        db.session.commit()

        return send_id
    except Exception as e:
        # Structured logging — do NOT log the raw email address or full exception message
        email_hash = hashlib.sha256(target.email.encode()).hexdigest()[:8]
        logger.error(
            "Failed to send email to target_hash=%s campaign_id=%s error_type=%s",
            email_hash,
            campaign.id,
            type(e).__name__
        )
        return None


def send_manager_summary(to_email: str, subject: str, html_body: str) -> None:
    """Send the post-campaign summary to the IT manager."""
    params: resend.Emails.SendParams = {
        "from": f"PhishGuard <{FROM_EMAIL}>",
        "to": [to_email],
        "subject": subject,
        "html": html_body,
    }
    try:
        resend.Emails.send(params)
    except Exception as e:
        logger.error("Failed to send manager summary: error_type=%s", type(e).__name__)
