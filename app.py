"""
app.py
Main Flask application — admin dashboard + tracking endpoints
"""

import os
import json
import stripe
from datetime import datetime, timedelta
from flask import Flask, request, render_template, render_template_string, redirect, url_for, jsonify, flash, send_file
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from io import BytesIO
import pandas as pd

from models import db, Organization, User, Target, Campaign, CampaignSend, TrainingModule
from ai_generators import generate_phishing_email, generate_training_content, generate_manager_summary, SCENARIO_LIBRARY
from email_engine import send_phishing_email, send_manager_summary

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///phishing_sim.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        org = Organization(
            name=request.form["company_name"],
            domain=request.form["company_domain"]
        )
        db.session.add(org)
        db.session.flush()

        user = User(
            org_id=org.id,
            email=request.form["email"],
            password_hash=bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        )
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form["password"]):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
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
        CampaignSend.sent_at >= datetime.utcnow() - timedelta(days=30)
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
    file = request.files["csv"]
    df = pd.read_csv(file)

    for _, row in df.iterrows():
        existing = Target.query.filter_by(
            org_id=current_user.org_id,
            email=row["email"]
        ).first()
        if existing:
            continue

        target = Target(
            org_id=current_user.org_id,
            email=row["email"],
            first_name=row.get("first_name", ""),
            last_name=row.get("last_name", ""),
            department=row.get("department", ""),
            job_title=row.get("job_title", "")
        )
        db.session.add(target)

    db.session.commit()
    flash(f"Imported {len(df)} targets", "success")
    return redirect(url_for("targets"))


# ─── Campaign Management ───────────────────────────────────────────────────────

@app.route("/campaigns/new", methods=["GET", "POST"])
@login_required
def new_campaign():
    if request.method == "POST":
        target_ids = request.form.getlist("target_ids")
        scenario = request.form["scenario"]
        difficulty = request.form["difficulty"]

        campaign = Campaign(
            org_id=current_user.org_id,
            name=request.form["name"],
            scenario=scenario,
            difficulty=difficulty,
            status="sending",
            sent_at=datetime.utcnow()
        )
        db.session.add(campaign)
        db.session.flush()

        org = Organization.query.get(current_user.org_id)
        sent_count = 0

        for target_id in target_ids:
            target = Target.query.get(target_id)
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
        flash(f"Campaign launched: {sent_count} emails sent", "success")
        return redirect(url_for("campaign_detail", campaign_id=campaign.id))

    targets = Target.query.filter_by(org_id=current_user.org_id).all()
    return render_template("new_campaign.html", targets=targets, scenarios=SCENARIO_LIBRARY)


@app.route("/campaigns/<int:campaign_id>")
@login_required
def campaign_detail(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.org_id != current_user.org_id:
        return "Forbidden", 403

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
        target = Target.query.get(send.target_id)
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

@app.route("/o/<send_id>")
def track_open(send_id):
    """1x1 tracking pixel — records email open."""
    send = CampaignSend.query.get(send_id)
    if send and not send.opened_at:
        send.opened_at = datetime.utcnow()
        db.session.commit()

    pixel = bytes.fromhex("47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b")
    return send_file(BytesIO(pixel), mimetype="image/gif")


@app.route("/c/<send_id>")
def track_click(send_id):
    """Phishing link landing page."""
    send = CampaignSend.query.get(send_id)
    if not send:
        return "Link expired", 404

    if not send.clicked_at:
        send.clicked_at = datetime.utcnow()
        target = Target.query.get(send.target_id)
        target.total_clicks += 1
        db.session.commit()

    return render_template("fake_login.html", send_id=send_id)


@app.route("/c/<send_id>/submit", methods=["POST"])
def track_credentials_submission(send_id):
    """User submitted creds on fake login — record but DO NOT store the actual creds."""
    send = CampaignSend.query.get(send_id)
    if not send:
        return "Link expired", 404

    if not send.credentials_submitted_at:
        send.credentials_submitted_at = datetime.utcnow()
        target = Target.query.get(send.target_id)
        target.total_credentials_submitted += 1
        db.session.commit()

    return redirect(url_for("training", send_id=send_id))


@app.route("/r/<send_id>")
def track_report(send_id):
    """User clicked the 'Report Phishing' link in the footer — good catch."""
    send = CampaignSend.query.get(send_id)
    if not send:
        return "Link expired", 404

    if not send.reported_at:
        send.reported_at = datetime.utcnow()
        target = Target.query.get(send.target_id)
        target.total_reports += 1
        db.session.commit()

    return render_template_string("""
    <!DOCTYPE html>
    <html><head><title>Great Catch!</title>
    <style>body { font-family: Arial; text-align: center; padding: 80px; background: #f0f8ff; }
           h1 { color: #28a745; } .box { background: white; padding: 40px; border-radius: 10px;
           max-width: 500px; margin: 0 auto; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }</style>
    </head><body>
    <div class="box">
      <h1>🎉 Great Catch!</h1>
      <p>You correctly identified that email as a phishing simulation.</p>
      <p>This is exactly the right behavior — thank you for staying alert!</p>
    </div></body></html>
    """)


# ─── Training ──────────────────────────────────────────────────────────────────

@app.route("/training/<send_id>")
def training(send_id):
    send = CampaignSend.query.get(send_id)
    if not send:
        return "Link expired", 404

    target = Target.query.get(send.target_id)
    campaign = Campaign.query.get(send.campaign_id)
    org = Organization.query.get(target.org_id)

    if not send.training_started_at:
        send.training_started_at = datetime.utcnow()
        db.session.commit()

    module = TrainingModule.query.filter_by(send_id=send_id).first()
    if not module:
        training_data = generate_training_content(
            scenario_key=campaign.scenario,
            target_first_name=target.first_name,
            company_name=org.name,
            email_they_received=send.email_body
        )
        module = TrainingModule(
            send_id=send_id,
            content_html=training_data["training_html"],
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
def complete_training(send_id):
    send = CampaignSend.query.get(send_id)
    if not send:
        return "Not found", 404

    data = request.get_json()
    send.training_quiz_score = data.get("score", 0)
    send.training_completed_at = datetime.utcnow()
    target = Target.query.get(send.target_id)
    target.total_trainings_completed += 1
    db.session.commit()

    return jsonify({"status": "complete"})


# ─── Reports ──────────────────────────────────────────────────────────────────

@app.route("/campaigns/<int:campaign_id>/export")
@login_required
def export_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.org_id != current_user.org_id:
        return "Forbidden", 403

    sends = CampaignSend.query.filter_by(campaign_id=campaign_id).all()
    rows = []
    for send in sends:
        target = Target.query.get(send.target_id)
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


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialized.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=False)
