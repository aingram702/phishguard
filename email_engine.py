"""
email_engine.py
SendGrid-based delivery with tracking
"""

import os
import uuid
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content, ReplyTo
from models import db, CampaignSend, Target, Campaign

sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")


def send_phishing_email(
    campaign: Campaign,
    target: Target,
    email_data: dict
) -> str:
    """Send one phishing email with unique tracking and store the record."""

    send_id = uuid.uuid4().hex
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
        response = sg.send(message)

        send_record = CampaignSend(
            id=send_id,
            campaign_id=campaign.id,
            target_id=target.id,
            email_subject=email_data["subject"],
            email_body=body_html,
            sender_email=email_data["sender_email"],
            sender_name=email_data["sender_name"],
            sent_at=datetime.utcnow()
        )
        db.session.add(send_record)
        db.session.commit()

        return send_id
    except Exception as e:
        print(f"[!] Failed to send to {target.email}: {e}")
        return None


def send_manager_summary(to_email: str, subject: str, html_body: str):
    """Send the post-campaign summary to the IT manager."""
    message = Mail(
        from_email=Email(os.getenv("SENDGRID_FROM_EMAIL"), "Phishing Sim Platform"),
        to_emails=To(to_email),
        subject=subject,
        html_content=Content("text/html", html_body)
    )
    sg.send(message)
