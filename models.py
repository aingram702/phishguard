"""
models.py
Full SQLAlchemy data model for the phishing sim platform
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class Organization(db.Model):
    """A customer company using the platform."""
    __tablename__ = "organizations"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    subscription_tier = db.Column(db.String(50), default="starter")
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    users = db.relationship("User", backref="organization", lazy=True)
    targets = db.relationship("Target", backref="organization", lazy=True)
    campaigns = db.relationship("Campaign", backref="organization", lazy=True)


class User(db.Model, UserMixin):
    """Admin user (the customer's IT person, not phishing targets)."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"))
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="admin")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Target(db.Model):
    """An employee being phished."""
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"))
    email = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    job_title = db.Column(db.String(150))
    risk_score = db.Column(db.Float, default=0.0)
    total_campaigns = db.Column(db.Integer, default=0)
    total_clicks = db.Column(db.Integer, default=0)
    total_credentials_submitted = db.Column(db.Integer, default=0)
    total_reports = db.Column(db.Integer, default=0)
    total_trainings_completed = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Campaign(db.Model):
    """A phishing campaign sent to targets."""
    __tablename__ = "campaigns"
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"))
    name = db.Column(db.String(200), nullable=False)
    scenario = db.Column(db.String(100))
    difficulty = db.Column(db.String(20), default="medium")
    status = db.Column(db.String(50), default="draft")
    scheduled_for = db.Column(db.DateTime)
    sent_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sends = db.relationship("CampaignSend", backref="campaign", lazy=True)


class CampaignSend(db.Model):
    """A single email sent to one target in one campaign."""
    __tablename__ = "campaign_sends"
    id = db.Column(db.String(64), primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"))
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"))
    email_subject = db.Column(db.String(300))
    email_body = db.Column(db.Text)
    sender_email = db.Column(db.String(200))
    sender_name = db.Column(db.String(200))
    sent_at = db.Column(db.DateTime)
    opened_at = db.Column(db.DateTime)
    clicked_at = db.Column(db.DateTime)
    credentials_submitted_at = db.Column(db.DateTime)
    reported_at = db.Column(db.DateTime)
    training_started_at = db.Column(db.DateTime)
    training_completed_at = db.Column(db.DateTime)
    training_quiz_score = db.Column(db.Integer)


class TrainingModule(db.Model):
    """AI-generated training content for a specific click event."""
    __tablename__ = "training_modules"
    id = db.Column(db.Integer, primary_key=True)
    send_id = db.Column(db.String(64), db.ForeignKey("campaign_sends.id"))
    content_html = db.Column(db.Text)
    quiz_json = db.Column(db.Text)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
