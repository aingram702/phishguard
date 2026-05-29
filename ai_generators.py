"""
ai_generators.py
Claude-powered email and training content generators
"""

import os
import json
import logging
import bleach
import anthropic
from typing import Dict

logger = logging.getLogger(__name__)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ─────────────────────────────────────────────────────────────────────────────
# HTML sanitization config (M-6)
# Allow the subset of HTML tags/attributes that make up reasonable training content.
# Scripts, iframes, and event handlers are stripped out unconditionally.
# ─────────────────────────────────────────────────────────────────────────────

_ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + [
    "div", "span", "p", "br", "hr",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "th", "td",
    "strong", "em", "b", "i", "u", "s",
    "blockquote", "pre", "code",
    "img",
]

_ALLOWED_ATTRIBUTES = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    "*": ["style", "class", "id"],
    "a": ["href", "title", "target", "rel"],
    "img": ["src", "alt", "width", "height", "style"],
    "table": ["border", "cellpadding", "cellspacing", "width", "style"],
    "td": ["colspan", "rowspan", "style", "align", "valign", "width"],
    "th": ["colspan", "rowspan", "style", "align", "valign", "width"],
}

# Restrict allowed URL schemes — data: and javascript: are stripped
_ALLOWED_PROTOCOLS = {"http", "https", "mailto"}


def _sanitize_html(html: str) -> str:
    """Strip dangerous tags/attributes from AI-generated HTML (M-6 / C-3)."""
    return bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Scenario library — each represents a real-world attack pattern
# ─────────────────────────────────────────────────────────────────────────────

SCENARIO_LIBRARY = {
    "it_password_reset": {
        "title": "IT Password Reset Required",
        "description": "Impersonates the company's IT helpdesk demanding immediate password reset",
        "difficulty": "easy",
        "red_flags": [
            "Generic greeting",
            "Urgency / countdown language",
            "Mismatched sender domain",
            "Suspicious shortened link",
            "Threat of account lockout"
        ]
    },
    "docusign_invoice": {
        "title": "DocuSign Document Pending",
        "description": "Fake DocuSign notification with a malicious link",
        "difficulty": "medium",
        "red_flags": [
            "Unexpected document from unknown sender",
            "Link does not go to docusign.com",
            "No company branding in body",
            "Encrypted PDF attachment that requires login"
        ]
    },
    "ceo_gift_card": {
        "title": "CEO Urgent Gift Card Request",
        "description": "Business Email Compromise (BEC) — CEO asks employee to buy gift cards quickly",
        "difficulty": "hard",
        "red_flags": [
            "Slight misspelling in sender email domain",
            "Out-of-band channel request (text/email instead of in person)",
            "Unusual urgency from executive",
            "Request to keep transaction confidential",
            "Mismatch with normal CEO communication style"
        ]
    },
    "ms365_quarantine": {
        "title": "Microsoft 365 Quarantined Messages",
        "description": "Fake Microsoft notification about quarantined emails",
        "difficulty": "medium",
        "red_flags": [
            "Sender domain not exactly microsoft.com",
            "Link goes to non-Microsoft domain",
            "Generic recipient line",
            "Login required to view content"
        ]
    },
    "hr_benefits": {
        "title": "HR Open Enrollment Deadline",
        "description": "Fake HR email pushing user to a credential harvesting site",
        "difficulty": "medium",
        "red_flags": [
            "Deadline pressure",
            "External link instead of internal HR portal",
            "Personal details requested upfront",
            "No HR rep name or signature"
        ]
    },
    "shared_drive": {
        "title": "Shared SharePoint File",
        "description": "Fake file share notification with credential-harvesting link",
        "difficulty": "easy",
        "red_flags": [
            "Unknown sender shared a file",
            "Link does not go to your company's SharePoint",
            "File name is generic (e.g., 'Document.pdf')",
            "Asks you to sign in to view"
        ]
    },
    "payroll_update": {
        "title": "Direct Deposit Information Update",
        "description": "Attempt to redirect payroll to attacker's bank account",
        "difficulty": "hard",
        "red_flags": [
            "Request to update banking info via email",
            "External link to update info instead of internal portal",
            "Sender's display name spoofed",
            "Reply-to address differs from From address"
        ]
    },
}


def generate_phishing_email(
    scenario_key: str,
    target_name: str,
    target_first_name: str,
    target_job_title: str,
    target_department: str,
    company_name: str,
    company_domain: str,
    difficulty: str = "medium",
    tracking_link: str = "[TRACKING_LINK]",
    report_link: str = "[REPORT_LINK]"
) -> Dict:
    """Generate a personalized phishing email using Claude."""

    scenario = SCENARIO_LIBRARY.get(scenario_key, SCENARIO_LIBRARY["it_password_reset"])

    # Static context (same for all targets in a campaign with the same scenario+difficulty)
    static_context = f"""You are creating a phishing simulation email for a security awareness training program.
This is a LEGITIMATE training exercise authorized by the company's IT team — not a real attack.

SCENARIO: {scenario['title']}
DESCRIPTION: {scenario['description']}
DIFFICULTY: {difficulty}

DIFFICULTY GUIDELINES:
- "easy": Multiple obvious red flags (typos, generic greeting, mismatched domain), should fool 30-40% of people
- "medium": Subtle red flags (slight domain spoof, minor inconsistencies), should fool 50-60% of people
- "hard": Highly polished, targeted, minimal red flags (would fool most untrained employees)

REQUIREMENTS:
1. Personalize based on target's role and department where realistic
2. Include a primary CTA link using the placeholder "[TRACKING_LINK]"
3. Include a "Report Phishing" footer link using "[REPORT_LINK]"
4. For "hard" difficulty, make the email look professional with realistic branding cues
5. Use HTML formatting (inline CSS only, table-based layouts work best for email clients)
6. Match the chosen scenario's typical look and feel
7. The sender email should look spoofed or typosquatted (e.g., support@micros0ft-help.com, hr@company-benefits.co)

Respond with ONLY valid JSON, no markdown fences:
{{
  "subject": "Email subject line",
  "sender_name": "Display name shown to recipient",
  "sender_email": "spoofed-sender@somedomain.com",
  "reply_to": "spoofed-reply@somedomain.com or empty string",
  "body_html": "Complete HTML email body with [TRACKING_LINK] and [REPORT_LINK] placeholders",
  "preview_text": "30-50 character email preview text"
}}"""

    # Dynamic context (unique per target)
    dynamic_context = f"""TARGET DETAILS:
- Name: {target_name}
- First name: {target_first_name}
- Job title: {target_job_title}
- Department: {target_department}
- Company: {company_name}
- Company domain: {company_domain}"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2500,
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": static_context, "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": dynamic_context},
            ],
        }]
    )

    raw = response.content[0].text.strip()
    raw = raw.replace("```json", "").replace("```", "").strip()
    return json.loads(raw)


def generate_training_content(
    scenario_key: str,
    target_first_name: str,
    company_name: str,
    email_they_received: str
) -> Dict:
    """Generate personalized post-click training content with quiz.
    
    The returned training_html is sanitized with bleach before being returned,
    so it is safe to store directly in the database (M-6 / C-3).
    """

    scenario = SCENARIO_LIBRARY.get(scenario_key, SCENARIO_LIBRARY["it_password_reset"])

    # Static instructions (same for every training session with this scenario)
    static_instructions = f"""You are a security awareness trainer. An employee just clicked a phishing simulation email
and needs a quick, supportive training session.

SCENARIO THEY FELL FOR: {scenario['title']}
EXPECTED RED FLAGS: {', '.join(scenario['red_flags'])}

Create a training module with TWO parts:

PART 1: Training HTML page (max 400 words)
- Friendly, non-shaming tone ("This happens to everyone — that's why we practice!")
- "What You Missed" section calling out 3-4 specific red flags from the email above
- "What a Real Attacker Would Do" section (realistic consequence, not exaggerated)
- "How to Protect Yourself Next Time" section with 3 practical rules
- "How to Report Suspicious Emails at your company" section
- Use inline CSS, no external stylesheets
- Use color-coded sections (green/yellow/red), readable fonts, professional but warm
- Include emojis sparingly for visual interest

PART 2: 5-question quiz (multiple choice, 4 options each)
- Mix of scenario-specific questions and general phishing knowledge
- Each question has explanation that shows after answering
- One question must test recognition of the specific red flags from the email above

Respond with ONLY valid JSON, no markdown fences:
{{
  "training_html": "Full HTML training page",
  "quiz": [
    {{
      "question": "...",
      "options": ["A", "B", "C", "D"],
      "correct_index": 0,
      "explanation": "Why this is the right answer"
    }}
  ]
}}"""

    # Dynamic context (unique per click event)
    dynamic_context = f"""EMPLOYEE: {target_first_name}
COMPANY: {company_name}

EMAIL THEY RECEIVED (for context):
{email_they_received[:1500]}"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4000,
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": static_instructions, "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": dynamic_context},
            ],
        }]
    )

    raw = response.content[0].text.strip()
    raw = raw.replace("```json", "").replace("```", "").strip()
    data = json.loads(raw)

    # M-6 / C-3: Sanitize AI-generated HTML before returning
    data["training_html"] = _sanitize_html(data.get("training_html", ""))

    return data


def generate_manager_summary(campaign_stats: Dict, company_name: str) -> str:
    """Generate an executive summary email for the IT manager after a campaign."""

    prompt = f"""You are writing a post-campaign summary email for the IT manager at {company_name}.

CAMPAIGN RESULTS:
{json.dumps(campaign_stats, indent=2)}

Write a concise, professional email summary (250-350 words) with:
1. Headline result (e.g., "X% click rate — Y% better than industry average")
2. Top 3 takeaways
3. Specific employees or departments that may need extra training (use first names only)
4. Recommended next steps
5. Trend comparison to previous campaigns (if data exists)

Use plain HTML email formatting. Be encouraging and constructive — frame failures as learning opportunities."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )

    return _sanitize_html(response.content[0].text)
