---
name: project-phishguard
description: PhishGuard — Flask-based phishing simulation and security awareness training platform
metadata:
  type: project
---

PhishGuard is a Flask + SQLAlchemy web app for running internal phishing simulation campaigns. It uses Anthropic Claude (claude-sonnet-4-6) to generate personalized phishing emails and post-click training content, Resend for email delivery, and Stripe for billing.

**Key files:** `app.py` (routes + tracking), `models.py` (SQLAlchemy ORM), `ai_generators.py` (Claude API calls), `email_engine.py` (Resend delivery + HMAC-signed send IDs).

**Why:** Security awareness training tool — employees receive simulated phishing emails; if they click, they get redirected to training. Results tracked per campaign.

**How to apply:** When suggesting DB changes, note that `db.create_all()` is the only migration mechanism — no Alembic. Schema changes require a fresh DB or manual migration.
