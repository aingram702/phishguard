# Contributing to PhishGuard

Thank you for your interest in contributing! This document covers how to get
your development environment set up, the standards we follow, and how to
submit changes.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Security Guidelines](#security-guidelines)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)

---

## Code of Conduct

This project is intended for **authorized security professionals**. All
contributors are expected to:

- Use and promote the platform only for legitimate, authorized security
  awareness training
- Treat all contributors and users with respect
- Report security vulnerabilities privately (see [SECURITY.md](SECURITY.md))

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/phishguard.git
   cd phishguard
   ```
3. **Add the upstream remote:**
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/phishguard.git
   ```

---

## Development Setup

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install all dependencies including dev tools
pip install -r requirements.txt
pip install pytest pytest-flask flake8 bandit

# Set up your environment
cp .env.example .env
# Edit .env — at minimum set FLASK_SECRET_KEY for local dev:
# FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Initialize the database
flask --app app init-db

# Run the development server
python app.py
```

The app will be available at [http://localhost:5000](http://localhost:5000).

---

## Project Structure

```
phishguard/
├── app.py              # All Flask routes and application setup
├── models.py           # SQLAlchemy ORM models
├── ai_generators.py    # Claude API calls — email + training generation
├── email_engine.py     # SendGrid delivery and HMAC token generation
├── requirements.txt    # Production + dev dependencies
├── .env.example        # Environment variable documentation
│
├── templates/
│   ├── base.html           # Shared layout
│   ├── dashboard.html      # Stats overview
│   ├── fake_login.html     # Simulated phishing page
│   ├── training.html       # Post-click training + quiz
│   └── report_success.html # "Great catch!" confirmation
│
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI pipeline
│
├── .gitignore
├── LICENSE
├── SECURITY.md
└── README.md
```

---

## Coding Standards

### Python

- **Style:** Follow [PEP 8](https://peps.python.org/pep-0008/) with a max line
  length of **120 characters**
- **Type hints:** Use them for all new functions
- **Docstrings:** Required for all public functions and classes
- **f-strings:** Preferred over `.format()` or `%` formatting
- **Imports:** Standard library → third-party → local, each group separated
  by a blank line

Run the linter before committing:
```bash
flake8 app.py models.py ai_generators.py email_engine.py --max-line-length=120
```

### Git Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new BEC scenario for finance department
fix: clamp training quiz score to 0-100 server-side
security: add HMAC signing to tracking send_ids
docs: update README deployment section
refactor: replace Query.get() with db.session.get()
```

Types: `feat` · `fix` · `security` · `docs` · `refactor` · `test` · `chore`

### HTML Templates

- All Jinja2 variables must be auto-escaped (the default) — only use `|safe`
  when the content has been explicitly sanitized with `bleach`
- No inline JavaScript that concatenates template variables into strings —
  use `|tojson` and DOM APIs (`textContent`, `createElement`) instead
- Add a comment explaining any `|safe` usage

---

## Security Guidelines

> These are hard requirements — PRs that violate them will not be merged.

### Never Do

| ❌ Forbidden | ✅ Required Instead |
|-------------|---------------------|
| `render_template_string(user_data)` | Use a real template file |
| `innerHTML = userString` | Use `textContent` / `createElement` |
| `datetime.utcnow()` | `datetime.now(timezone.utc)` |
| `Model.query.get(id)` | `db.session.get(Model, id)` |
| `print(email_address)` | `logger.error("...", hash(email))` |
| Store submitted passwords | Discard immediately — record timestamp only |
| Hardcode API keys | Read from `os.getenv()` only |
| Skip CSRF on authenticated POST | Use `@csrf.exempt` only for public tracking endpoints, with a comment |

### Adding New Routes

- **Authenticated routes:** Must have `@login_required` and CSRF protection
  (automatic via `CSRFProtect`)
- **Public tracking routes:** Must have `@csrf.exempt` with an explanatory
  comment, `@limiter.limit(...)`, and call `_resolve_send()` for HMAC
  verification before touching the database
- **Input validation:** Validate and sanitize all form/query inputs before
  use; whitelist known-good values wherever possible

### Adding New AI-Generated Content

Any new content generated by Claude that will be rendered as HTML **must** be
passed through `_sanitize_html()` from `ai_generators.py` before storage or
rendering.

---

## Submitting a Pull Request

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes** following the coding standards above

3. **Run the checks locally:**
   ```bash
   # Lint
   flake8 app.py models.py ai_generators.py email_engine.py --max-line-length=120

   # Security scan
   bandit -r app.py models.py ai_generators.py email_engine.py -l -i

   # Syntax check
   python -c "import ast; [ast.parse(open(f).read()) for f in ['app.py','models.py','ai_generators.py','email_engine.py']]; print('OK')"
   ```

4. **Push and open a PR** against the `main` branch

5. **Fill in the PR template** — describe what changed and why, link any
   relevant issues, and confirm you've read the security guidelines

6. A maintainer will review within **5 business days**

---

## Reporting Bugs

Open a [GitHub Issue](../../issues/new) with:

- **Description** of the bug
- **Steps to reproduce**
- **Expected vs. actual behavior**
- **Environment** (Python version, OS, relevant env vars — no secrets!)

For **security vulnerabilities**, see [SECURITY.md](SECURITY.md) instead of
opening a public issue.
