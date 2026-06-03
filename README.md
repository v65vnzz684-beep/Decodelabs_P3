# 🎣 Phishing Email Triage Analyzer

**Cybersecurity Awareness Training Tool**
Built for the DecodeLabs Cybersecurity Training Programme — Batch 2026

---

## What is this?

This is a command-line Python tool that scans an email (subject, sender, and body) for known phishing indicators, assigns a **danger score**, and delivers a clear triage verdict — just like a real SOC analyst would.

It is designed as a **learning tool** for interns and non-technical staff. Every check is explained in plain English inside the code itself.

---

## What does "phishing" mean?

Phishing is when a cybercriminal sends a fake email pretending to be a trusted person or organisation (your bank, Microsoft, your CEO) in order to steal your password, money, or personal information.

Phishers exploit four psychological levers:

| Lever | What it looks like |
|---|---|
| **Urgency** | "Your account will be suspended in 24 hours!" |
| **Fear** | "Legal action will be taken if you don't respond." |
| **Greed** | "You have been selected as our prize winner!" |
| **Authority** | "This is the CEO — process this wire transfer now." |

---

## Features

- **Sample email runner** — analyses 3 built-in examples (legitimate email, mass phishing, CEO fraud) so you can see the tool in action immediately
- **Manual email analyser** — paste any email you want to check
- **Red flag reference checklist** — a static 13-point reference card to keep open while reviewing suspicious emails
- **Danger score bar** — visual progress bar showing threat severity at a glance
- **Triage verdict** — one of three outcomes with a clear action step

---

## How the scoring works

Each check carries a point value based on how strong an indicator it is:

| Check | Points |
|---|---|
| Sender domain mismatch | +2 |
| Urgency trigger words | +1 per keyword |
| Fear / threat language | +1 per keyword |
| Greed / reward language | +1 per keyword |
| Authority impersonation | +1 per keyword |
| Credential / PII request | **+2 per phrase** |
| Suspicious URL patterns | **+2 per match** |
| Secrecy / bypass instructions | **+3 flat** |

Credential requests, suspicious links, and secrecy instructions are weighted higher because they are the most direct attack vectors.

### Verdict thresholds

| Score | Verdict | Action |
|---|---|---|
| 0 | ✅ Safe | Close the ticket |
| 1 – 4 | ⚠️ Suspicious | Warn the user, verify via phone |
| 5+ | 🚨 Malicious | Block domain, escalate to security team |

---

## Requirements

- Python 3.8 or higher
- No external libraries — uses only the built-in `re` module

---

## How to run

```bash
python phishing_analyzer.py
```

You will see a menu with four options:

```
[1]  Run the 3 built-in sample emails
[2]  Analyse my own email
[3]  View the Red Flag Reference Checklist
[4]  Quit
```

### Option 1 — Sample emails

Runs all three pre-loaded examples automatically. Great for understanding how the scoring works before analysing real emails.

### Option 2 — Analyse your own email

You will be prompted to enter:
1. The **From** field (e.g. `Support <help@suspicious.com>`)
2. The **Subject** line
3. The **Body** — paste or type it line by line, then press **Enter on a blank line** to finish

### Option 3 — Reference Checklist

Displays a 13-point reference card grouped by category (Sender, Urgency, Fear, Greed, Authority, Credentials, Links, Secrecy, Attachments). Keep it open while reviewing real emails.

---

## File structure

```
phishing_analyzer.py    ← main script (run this)
README.md               ← this file
```

---

## Code walkthrough (for beginners)

The script is divided into 9 clearly labelled sections:

| Section | What it does |
|---|---|
| 1 — Trigger word lists | Four keyword lists (urgency, fear, greed, authority) |
| 2 — URL patterns | Regex patterns for suspicious links |
| 3 — Sample emails | Three built-in test cases |
| 4 — Analysis engine | `scan_email()` — the core logic |
| 5 — Output helpers | `print_triage_result()` — formats the results |
| 6 — Sample runner | `run_sample_emails()` — loops through the 3 samples |
| 7 — Manual input | `manual_analysis()` — collects user-typed email |
| 8 — Reference checklist | `show_checklist()` — static 13-point reference card |
| 9 — Main menu | `main()` — the entry point and menu loop |

Every function has a docstring explaining what it does, what it receives, and what it returns.

---

## The 8 checks explained

### Check 1 — Sender domain mismatch
A genuine PayPal email comes **from** `paypal.com`. If the display name says "PayPal" but the actual address is `@paypa1-secure.com`, that is impersonation.

### Check 2 — Urgency language
Words like `urgent`, `act now`, `expires in`, `suspended` are designed to make you panic and skip critical thinking.

### Check 3 — Fear / threat language
Phrases like `legal action`, `arrested`, `unauthorized access`, `unusual sign-in` trigger anxiety and override rational judgement.

### Check 4 — Greed / reward language
`you have won`, `lottery`, `claim your prize` — these exploit wishful thinking to get you to click.

### Check 5 — Authority impersonation
References to `ceo`, `it support`, `microsoft`, `irs`, `bank` borrow trust from organisations you already respect.

### Check 6 — Credential / PII requests
`enter your password`, `provide your otp`, `enter credit card` — **no legitimate service asks for this over email.** Ever. This check carries double weight.

### Check 7 — Suspicious URL patterns
Six patterns are checked: unencrypted `http://` links, raw IP addresses, URL shorteners, typosquatted brand names, combo-squatting keywords, and high-abuse top-level domains (`.xyz`, `.tk`). Each match adds 2 points.

### Check 8 — Secrecy / bypass instructions
`do not discuss`, `bypass standard procedure`, `keep this confidential` — these are the hallmarks of **Business Email Compromise (BEC)**. This check adds 3 points flat because it is one of the strongest social engineering signals.

---

## The triage decision tree

```
Incoming suspicious email
         │
         ▼
   Run all 8 checks
         │
    ┌────┴────┐
  Score 0   Score 1-4   Score 5+
    │           │            │
    ▼           ▼            ▼
  SAFE      SUSPICIOUS    MALICIOUS
  Close      Warn user    Block domain
  ticket     Verify via   Escalate to
             phone        security team
```

---

## Golden rule

> **Pause → Verify → Report**
>
> When in doubt, do not click. Pick up the phone and call the sender on a number you already know. Then report the email to your IT security team.

---

## Disclaimer






This tool is designed for **training and educational purposes**. It performs keyword and pattern matching on plain text — it does not execute links, open attachments, or connect to the internet. It is not a substitute for a professional email security gateway (e.g. Microsoft Defender, Proofpoint, Mimecast).
##  Part of DecodeLabs Cybersecurity Training

> **Project 3 — Phishing Awareness Analysis Project**  
> Batch 2026 | Powered by DecodeLabs  
> [www.decodelabs.tech](https://www.decodelabs.tech)
