"""
app.py
Main Flask application — admin dashboard + tracking endpoints
"""

import os
import re
import hmac
import hashlib
import json
import logging
import stripe
from datetime import datetime, timezone, timedelta
from flask import Flask, request, render_template, redirect, url_for, jsonify, flash, send_file, abort
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from io import BytesIO
import pandas as pd

from models import db, Organization, User, Target, Campaign, CampaignSend, TrainingModule
from ai_generators import generate_phishing_email, generate_training_content, generate_manager_summary, SCENARIO_LIBRARY
from email_engine import send_phishing_email, send_manager_summary

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s"
)
logger = logging.getLogger(__name__)

# ─── App Configuration ────────────────────────────────────────────────────────

app = Flask(__name__)

# C-1 / H-1: Enforce presence of SECRET_KEY — fail fast rather than run insecurely
_secret_key = os.getenv("FLASK_SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is not set. "
        "Set it to a long random string before starting the server."
    )
app.config["SECRET_KEY"] = _secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///phishing_sim.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["WTF_CSRF_ENABLED"] = True
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # H-4: 5 MB upload limit

# HMAC key for send_id signing (H-3 / H-5)
_HMAC_SECRET = os.getenv("SEND_ID_HMAC_SECRET", _secret_key).encode()

db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)  # C-1: CSRF protection for all forms
login_manager = LoginManager(app)
login_manager.login_view = "login"

# C-4: Rate limiter — storage URI can be overridden with RATELIMIT_STORAGE_URI env var
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://")
)

# M-5: Secure HTTP headers
# CSP is permissive enough for Bootstrap CDN + inline styles needed for email previews
_csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
    "style-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
    "img-src": ["'self'", "data:"],
    "font-src": ["'self'", "fonts.googleapis.com", "fonts.gstatic.com"],
    "frame-ancestors": ["'none'"],
}
Talisman(
    app,
    force_https=os.getenv("FLASK_ENV") == "production",
    strict_transport_security=os.getenv("FLASK_ENV") == "production",
    content_security_policy=_csp,
    x_content_type_options=True,
    x_frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
)

# H-2: Only set Stripe key if the env var actually exists
if os.getenv("STRIPE_SECRET_KEY"):
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")


# ─── HMAC Utilities ───────────────────────────────────────────────────────────

def _sign_send_id(raw_id: str) -> str:
    """Return send_id with an HMAC suffix: '<uuid>.<hmac>'."""
    sig = hmac.new(_HMAC_SECRET, raw_id.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{raw_id}.{sig}"


def _verify_send_id(signed_id: str) -> str | None:
    """Verify the HMAC and return the raw UUID, or None if invalid."""
    parts = signed_id.rsplit(".", 1)
    if len(parts) != 2:
        return None
    raw_id, provided_sig = parts
    expected_sig = hmac.new(_HMAC_SECRET, raw_id.encode(), hashlib.sha256).hexdigest()[:16]
    if hmac.compare_digest(provided_sig, expected_sig):
        return raw_id
    return None


# ─── Allowed flash categories whitelist (M-2) ────────────────────────────────

_SAFE_FLASH_CATEGORIES = {"success", "error", "warning", "info"}


def safe_flash(message: str, category: str = "info") -> None:
    """Flash a message, ensuring the category is a known safe value."""
    if category not in _SAFE_FLASH_CATEGORIES:
        category = "info"
    flash(message, category)


# ─── Auth ──────────────────────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # L-2: SQLAlchemy 2.0 compat


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        company_domain = request.form.get("company_domain", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # M-1: Input validation
        if not company_name or len(company_name) > 200:
            safe_flash("Company name must be between 1 and 200 characters.", "error")
            return render_template("signup.html")
        if not company_domain or len(company_domain) > 200:
            safe_flash("Company domain must be between 1 and 200 characters.", "error")
            return render_template("signup.html")
        if not _is_valid_email(email):
            safe_flash("Invalid email address.", "error")
            return render_template("signup.html")
        if len(password) < 12:
            safe_flash("Password must be at least 12 characters.", "error")
            return render_template("signup.html")
        if len(password) > 128:
            safe_flash("Password must be 128 characters or fewer.", "error")
            return render_template("signup.html")

        if User.query.filter_by(email=email).first():
            safe_flash("An account with that email already exists.", "error")
            return render_template("signup.html")

        org = Organization(name=company_name, domain=company_domain)
        db.session.add(org)
        db.session.flush()

        user = User(
            org_id=org.id,
            email=email,
            password_hash=bcrypt.generate_password_hash(password).decode("utf-8")
        )
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        safe_flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ─── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    org_id = current_user.org_id
    total_targets = Target.query.filter_by(org_id=org_id).count()
    total_campaigns = Campaign.query.filter_by(org_id=org_id).count()

    recent_sends = db.session.query(CampaignSend).join(Campaign).filter(
        Campaign.org_id == org_id,
        CampaignSend.sent_at >= datetime.now(timezone.utc) - timedelta(days=30)  # L-1
    ).all()

    sent_count = len(recent_sends)
    clicked_count = sum(1 for s in recent_sends if s.clicked_at)
    creds_count = sum(1 for s in recent_sends if s.credentials_submitted_at)
    reported_count = sum(1 for s in recent_sends if s.reported_at)

    click_rate = (clicked_count / sent_count * 100) if sent_count > 0 else 0
    report_rate = (reported_count / sent_count * 100) if sent_count > 0 else 0

    return render_template("dashboard.html",
        total_targets=total_targets,
        total_campaigns=total_campaigns,
        sent_count=sent_count,
        clicked_count=clicked_count,
        creds_count=creds_count,
        reported_count=reported_count,
        click_rate=round(click_rate, 1),
        report_rate=round(report_rate, 1)
    )


# ─── Target Management ─────────────────────────────────────────────────────────

@app.route("/targets")
@login_required
def targets():
    targets = Target.query.filter_by(org_id=current_user.org_id).all()
    return render_template("targets.html", targets=targets)


@app.route("/targets/upload", methods=["POST"])
@login_required
def upload_targets():
    """Bulk upload targets via CSV. CSV columns: email, first_name, last_name, department, job_title"""
    # H-4: File type and size validation
    file = request.files.get("csv")
    if not file or not file.filename:
        safe_flash("No file uploaded.", "error")
        return redirect(url_for("targets"))

    if not file.filename.lower().endswith(".csv"):
        safe_flash("Only .csv files are accepted.", "error")
        return redirect(url_for("targets"))

    try:
        df = pd.read_csv(file)
    except Exception as e:
        logger.warning("CSV parse error from org %s: %s", current_user.org_id, type(e).__name__)
        safe_flash("Could not parse the uploaded file. Ensure it is a valid CSV.", "error")
        return redirect(url_for("targets"))

    if "email" not in df.columns:
        safe_flash("CSV must contain an 'email' column.", "error")
        return redirect(url_for("targets"))

    imported = 0
    for _, row in df.iterrows():
        email = str(row.get("email", "")).strip().lower()
        if not _is_valid_email(email):
            continue

        existing = Target.query.filter_by(
            org_id=current_user.org_id,
            email=email
        ).first()
        if existing:
            continue

        target = Target(
            org_id=current_user.org_id,
            email=email,
            first_name=str(row.get("first_name", ""))[:100],
            last_name=str(row.get("last_name", ""))[:100],
            department=str(row.get("department", ""))[:100],
            job_title=str(row.get("job_title", ""))[:150]
        )
        db.session.add(target)
        imported += 1

    db.session.commit()
    safe_flash(f"Imported {imported} targets", "success")
    return redirect(url_for("targets"))


# ─── Campaign Management ───────────────────────────────────────────────────────

@app.route("/campaigns/new", methods=["GET", "POST"])
@login_required
def new_campaign():
    if request.method == "POST":
        target_ids = request.form.getlist("target_ids")
        scenario = request.form.get("scenario", "")
        difficulty = request.form.get("difficulty", "medium")
        name = request.form.get("name", "").strip()

        # Whitelist scenario and difficulty to known values
        if scenario not in SCENARIO_LIBRARY:
            safe_flash("Invalid scenario selected.", "error")
            return redirect(url_for("new_campaign"))
        if difficulty not in ("easy", "medium", "hard"):
            difficulty = "medium"
        if not name or len(name) > 200:
            safe_flash("Campaign name must be between 1 and 200 characters.", "error")
            return redirect(url_for("new_campaign"))

        campaign = Campaign(
            org_id=current_user.org_id,
            name=name,
            scenario=scenario,
            difficulty=difficulty,
            status="sending",
            sent_at=datetime.now(timezone.utc)  # L-1
        )
        db.session.add(campaign)
        db.session.flush()

        org = db.session.get(Organization, current_user.org_id)  # L-2
        sent_count = 0

        for target_id in target_ids:
            target = db.session.get(Target, int(target_id)) if str(target_id).isdigit() else None  # L-2
            if not target or target.org_id != current_user.org_id:
                continue

            email_data = generate_phishing_email(
                scenario_key=scenario,
                target_name=f"{target.first_name} {target.last_name}",
                target_first_name=target.first_name,
                target_job_title=target.job_title or "Employee",
                target_department=target.department or "General",
                company_name=org.name,
                company_domain=org.domain,
                difficulty=difficulty
            )

            send_id = send_phishing_email(campaign, target, email_data)
            if send_id:
                target.total_campaigns += 1
                sent_count += 1

        campaign.status = "sent"
        db.session.commit()
        safe_flash(f"Campaign launched: {sent_count} emails sent", "success")
        return redirect(url_for("campaign_detail", campaign_id=campaign.id))

    targets = Target.query.filter_by(org_id=current_user.org_id).all()
    return render_template("new_campaign.html", targets=targets, scenarios=SCENARIO_LIBRARY)


@app.route("/campaigns/<int:campaign_id>")
@login_required
def campaign_detail(campaign_id):
    campaign = db.session.get(Campaign, campaign_id)  # L-2
    if campaign is None:
        abort(404)
    if campaign.org_id != current_user.org_id:
        abort(403)

    sends = CampaignSend.query.filter_by(campaign_id=campaign_id).all()
    stats = {
        "sent": len(sends),
        "opened": sum(1 for s in sends if s.opened_at),
        "clicked": sum(1 for s in sends if s.clicked_at),
        "credentials": sum(1 for s in sends if s.credentials_submitted_at),
        "reported": sum(1 for s in sends if s.reported_at),
        "trained": sum(1 for s in sends if s.training_completed_at),
    }

    detail_rows = []
    for send in sends:
        target = db.session.get(Target, send.target_id)  # L-2
        detail_rows.append({
            "target": target,
            "send": send,
            "status": _compute_status(send)
        })

    return render_template("campaign_detail.html", campaign=campaign, stats=stats, rows=detail_rows)


def _compute_status(send):
    if send.reported_at:
        return ("reported", "✅ Reported Phishing")
    if send.credentials_submitted_at:
        return ("creds", "🚨 Submitted Credentials")
    if send.clicked_at:
        return ("clicked", "⚠️ Clicked Link")
    if send.opened_at:
        return ("opened", "👁 Opened Email")
    return ("sent", "📧 Sent")


# ─── Tracking Endpoints ────────────────────────────────────────────────────────

def _resolve_send(signed_id: str) -> CampaignSend | None:
    """Verify HMAC and look up the CampaignSend record. Returns None on failure."""
    raw_id = _verify_send_id(signed_id)
    if raw_id is None:
        return None
    return db.session.get(CampaignSend, raw_id)  # L-2


@app.route("/o/<send_id>")
@limiter.limit("60 per minute")  # C-4: rate limit
@csrf.exempt  # Tracking pixels are plain GET requests, no form
def track_open(send_id):
    """1x1 tracking pixel — records email open."""
    send = _resolve_send(send_id)  # H-5: HMAC check
    if send and not send.opened_at:
        send.opened_at = datetime.now(timezone.utc)  # L-1
        db.session.commit()

    pixel = bytes.fromhex("47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b")
    return send_file(BytesIO(pixel), mimetype="image/gif")


@app.route("/c/<send_id>")
@limiter.limit("20 per minute")  # C-4
@csrf.exempt
def track_click(send_id):
    """Phishing link landing page."""
    send = _resolve_send(send_id)  # H-5
    if not send:
        return "Link expired", 404

    if not send.clicked_at:
        send.clicked_at = datetime.now(timezone.utc)  # L-1
        target = db.session.get(Target, send.target_id)  # L-2
        if target:
            target.total_clicks += 1
        db.session.commit()

    return render_template("fake_login.html", send_id=send_id)


@app.route("/c/<send_id>/submit", methods=["POST"])
@limiter.limit("20 per minute")  # C-4
@csrf.exempt  # Public endpoint — no session to protect; payload is intentionally discarded
def track_credentials_submission(send_id):
    """User submitted creds on fake login — record but DO NOT store the actual creds."""
    send = _resolve_send(send_id)  # H-5
    if not send:
        return "Link expired", 404

    # Explicitly discard any submitted credentials — never log or store them
    # (Email/password fields are intentionally ignored here)

    if not send.credentials_submitted_at:
        send.credentials_submitted_at = datetime.now(timezone.utc)  # L-1
        target = db.session.get(Target, send.target_id)  # L-2
        if target:
            target.total_credentials_submitted += 1
        db.session.commit()

    return redirect(url_for("training", send_id=send_id))


@app.route("/r/<send_id>")
@limiter.limit("20 per minute")  # C-4
@csrf.exempt
def track_report(send_id):
    """User clicked the 'Report Phishing' link in the footer — good catch."""
    send = _resolve_send(send_id)  # H-5
    if not send:
        return "Link expired", 404

    if not send.reported_at:
        send.reported_at = datetime.now(timezone.utc)  # L-1
        target = db.session.get(Target, send.target_id)  # L-2
        if target:
            target.total_reports += 1
        db.session.commit()

    # C-2: Use a real template instead of render_template_string
    return render_template("report_success.html")


# ─── Training ──────────────────────────────────────────────────────────────────

@app.route("/training/<send_id>")
@limiter.limit("30 per minute")  # C-4
@csrf.exempt
def training(send_id):
    send = _resolve_send(send_id)  # H-5
    if not send:
        return "Link expired", 404

    target = db.session.get(Target, send.target_id)  # L-2
    campaign = db.session.get(Campaign, send.campaign_id)  # L-2
    org = db.session.get(Organization, target.org_id)  # L-2

    if not send.training_started_at:
        send.training_started_at = datetime.now(timezone.utc)  # L-1
        db.session.commit()

    module = TrainingModule.query.filter_by(send_id=_verify_send_id(send_id)).first()
    if not module:
        training_data = generate_training_content(
            scenario_key=campaign.scenario,
            target_first_name=target.first_name,
            company_name=org.name,
            email_they_received=send.email_body
        )
        module = TrainingModule(
            send_id=_verify_send_id(send_id),
            content_html=training_data["training_html"],  # Sanitized in ai_generators.py (M-6)
            quiz_json=json.dumps(training_data["quiz"])
        )
        db.session.add(module)
        db.session.commit()

    return render_template("training.html",
        send_id=send_id,
        content=module.content_html,
        quiz=json.loads(module.quiz_json)
    )


@app.route("/training/<send_id>/complete", methods=["POST"])
@limiter.limit("10 per minute")  # C-4
@csrf.exempt
def complete_training(send_id):
    send = _resolve_send(send_id)  # H-5
    if not send:
        return "Not found", 404

    data = request.get_json(silent=True) or {}
    # M-7: Clamp and validate the quiz score
    try:
        score = int(data.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))  # Clamp to 0-100

    send.training_quiz_score = score
    send.training_completed_at = datetime.now(timezone.utc)  # L-1
    target = db.session.get(Target, send.target_id)  # L-2
    if target:
        target.total_trainings_completed += 1
    db.session.commit()

    return jsonify({"status": "complete"})


# ─── Reports ──────────────────────────────────────────────────────────────────

@app.route("/campaigns/<int:campaign_id>/export")
@login_required
def export_campaign(campaign_id):
    campaign = db.session.get(Campaign, campaign_id)  # L-2
    if campaign is None:
        abort(404)
    if campaign.org_id != current_user.org_id:
        abort(403)

    sends = CampaignSend.query.filter_by(campaign_id=campaign_id).all()
    rows = []
    for send in sends:
        target = db.session.get(Target, send.target_id)  # L-2
        rows.append({
            "Email": target.email,
            "Name": f"{target.first_name} {target.last_name}",
            "Department": target.department,
            "Sent": send.sent_at,
            "Opened": send.opened_at or "",
            "Clicked": send.clicked_at or "",
            "Submitted Credentials": send.credentials_submitted_at or "",
            "Reported as Phishing": send.reported_at or "",
            "Training Completed": send.training_completed_at or "",
            "Quiz Score": send.training_quiz_score or ""
        })

    df = pd.DataFrame(rows)
    output = BytesIO()
    df.to_excel(output, index=False, engine="openpyxl")
    output.seek(0)

    return send_file(output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=f"campaign_{campaign_id}_report.xlsx")


# ─── Utilities ────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _is_valid_email(email: str) -> bool:
    """Basic RFC-ish email format check."""
    return bool(email and len(email) <= 200 and _EMAIL_RE.match(email))


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialized.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=5000, debug=False)  # Bind to localhost only in dev
