# AI-Phishing-Simulation-Platform
KnowBe4 for SMBs at 1/10th the price, with AI-personalized training.


# Architecture 
┌─────────────────────────────────────────────────────────────┐
│                    PHISHING SIM PLATFORM                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  [Admin Dashboard]  ──>  [Campaign Manager]                  │
│       (Flask)                  │                              │
│                                ↓                              │
│                    [AI Email Generator] (Claude)             │
│                                │                              │
│                                ↓                              │
│                    [SendGrid] ──> Target Inbox               │
│                                                               │
│  Target clicks link ──> [Tracking Server] ──> [DB]           │
│                                │                              │
│                                ↓                              │
│                    [Landing Page]                            │
│                                │                              │
│                                ↓                              │
│                    [AI Training Generator] (Claude)          │
│                                │                              │
│                                ↓                              │
│                    [Quiz + Completion Tracking]              │
│                                │                              │
│                                ↓                              │
│  [Manager Reports] <── [Stats Engine] ──> [Stripe Billing]   │
│                                                               │
└─────────────────────────────────────────────────────────────┘

