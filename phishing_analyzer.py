# PROJECT 3: Phishing Awareness Analysis
# DecodeLabs Cybersecurity - Batch 2026

import re

# --- Psychological trigger word lists ---

URGENCY_TRIGGERS = [
    "urgent", "immediately", "account locked", "expires in",
    "act now", "limited time", "within 24 hours", "asap",
    "your account will be", "suspended", "verify now",
]

FEAR_TRIGGERS = [
    "legal action", "lawsuit", "police", "arrested", "penalty",
    "unauthorized access", "suspicious activity", "security alert",
    "your account has been compromised", "unusual sign-in",
]

GREED_TRIGGERS = [
    "you have won", "congratulations", "prize", "reward",
    "free gift", "lottery", "claim your", "selected winner",
    "bonus", "unclaimed",
]

AUTHORITY_TRIGGERS = [
    "ceo", "it support", "help desk", "government", "irs",
    "bank", "paypal", "amazon", "microsoft", "google",
    "strictly confidential", "do not share", "bypass",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "confirm your password", "update billing",
    "verify your identity", "provide your otp", "click here to login",
    "reset your password", "enter credit card", "social security",
]

SECRECY_PHRASES = [
    "do not discuss", "bypass", "do not tell",
    "keep this confidential", "don't share",
]

# --- Suspicious URL patterns (regex) ---

SUSPICIOUS_URL_PATTERNS = [
    r"http://",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"bit\.ly|tinyurl|t\.co|goo\.gl",
    r"amaz0n|paypa1|micros0ft|g00gle",
    r"login-update|secure-alert|verify-account|account-confirm",
    r"\.xyz|\.tk|\.ml|\.ga|\.cf",
]

# --- Built-in sample emails ---

SAMPLE_EMAILS = [
    {
        "label":   "Sample 1 — Legitimate internal email",
        "sender":  "Project Manager <sarah.lee@company.com>",
        "subject": "Q3 Project Status Update — Non-Urgent",
        "body":    (
            "Hi Team, please review the attached project status for Q3 "
            "at your earliest convenience. No immediate action is required. "
            "Thanks, Sarah."
        ),
    },
    {
        "label":   "Sample 2 — Mass phishing (fake PayPal)",
        "sender":  "PayPal Support <support@paypa1-secure.com>",
        "subject": "Urgent: Your PayPal account has been suspended!",
        "body":    (
            "Your account has been suspended due to suspicious activity. "
            "Click here to login and verify your identity immediately: "
            "http://paypa1-secure.xyz/login. "
            "Act now or your account will be permanently closed."
        ),
    },
    {
        "label":   "Sample 3 — CEO fraud / Business Email Compromise",
        "sender":  "CEO — STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>",
        "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        "body":    (
            "URGENT: Process the attached wire transfer instruction immediately. "
            "This is critical and must remain STRICTLY CONFIDENTIAL. "
            "Do not discuss with anyone. Bypass standard procedure. Thank you."
        ),
    },
]


# --- Core analysis function ---

def scan_email(subject, sender, body):
    red_flags = []
    score     = 0
    full_text = (subject + " " + sender + " " + body).lower()

    KNOWN_BRANDS = ["microsoft", "google", "amazon", "paypal", "apple", "bank"]
    if re.search(r"<[^>]+@(?!(?:gmail\.com|yahoo\.com|outlook\.com))[^>]+>", sender):
        if any(brand in sender.lower() for brand in KNOWN_BRANDS):
            red_flags.append("🚩 [1] Sender mismatch — brand name in display name but domain does not match.")
            score += 2

    found = [kw for kw in URGENCY_TRIGGERS if kw in full_text]
    if found:
        red_flags.append(f"🚩 [2] Urgency triggers → {', '.join(found)}")
        score += len(found)

    found = [kw for kw in FEAR_TRIGGERS if kw in full_text]
    if found:
        red_flags.append(f"🚩 [3] Fear/threat language → {', '.join(found)}")
        score += len(found)

    found = [kw for kw in GREED_TRIGGERS if kw in full_text]
    if found:
        red_flags.append(f"🚩 [4] Greed/reward language → {', '.join(found)}")
        score += len(found)

    found = [kw for kw in AUTHORITY_TRIGGERS if kw in full_text]
    if found:
        red_flags.append(f"🚩 [5] Authority impersonation → {', '.join(found)}")
        score += len(found)

    found = [kw for kw in CREDENTIAL_REQUEST_PHRASES if kw in full_text]
    if found:
        red_flags.append(f"🚩 [6] Credential/PII request → {', '.join(found)}")
        score += len(found) * 2

    matches = [p for p in SUSPICIOUS_URL_PATTERNS if re.search(p, body, re.IGNORECASE)]
    if matches:
        red_flags.append(f"🚩 [7] Suspicious URL pattern(s) — {len(matches)} match(es).")
        score += len(matches) * 2

    found = [p for p in SECRECY_PHRASES if p in full_text]
    if found:
        red_flags.append(f"🚩 [8] Secrecy/bypass instruction → {', '.join(found)}")
        score += 3

    if score == 0:
        verdict = "✅  SAFE       — No phishing indicators detected. Close the ticket."
    elif score <= 4:
        verdict = "⚠️   SUSPICIOUS  — Warn the user. Verify through a separate channel."
    else:
        verdict = "🚨  MALICIOUS   — Block domain and escalate to the security team immediately."

    return verdict, score, red_flags


# --- Display helpers ---

def divider(char="─", width=60):
    print(char * width)


def print_triage_result(label, sender, subject, body, show_email=True):
    print()
    divider("═")
    print(f"  📧  {label}")
    divider("═")

    if show_email:
        print(f"  From    : {sender}")
        print(f"  Subject : {subject}")
        preview = body if len(body) <= 120 else body[:117] + "..."
        print(f"  Body    : {preview}")
        divider()

    verdict, score, flags = scan_email(subject, sender, body)

    filled = min(round((score / 20) * 20), 20)
    bar    = "█" * filled + "░" * (20 - filled)

    print(f"  Danger score : {score:>3}  [{bar}]")
    print(f"  Verdict      : {verdict}")

    if flags:
        print()
        print("  Red flags found:")
        for flag in flags:
            print(f"    {flag}")
    else:
        print("\n  ✅  No red flags detected.")

    print()
    divider("═")


# --- Menu actions ---

def run_sample_emails():
    print()
    print("  Running 3 built-in sample emails...\n")
    for sample in SAMPLE_EMAILS:
        print_triage_result(
            label=sample["label"], sender=sample["sender"],
            subject=sample["subject"], body=sample["body"],
            show_email=True,
        )


def manual_analysis():
    print()
    divider("═")
    print("  ✍️   MANUAL EMAIL ANALYSIS")
    divider("═")

    sender  = input("  From    : ").strip()
    subject = input("  Subject : ").strip()
    print("  Body (press Enter on a blank line to finish):")
    print()

    lines = []
    while True:
        line = input("  │ ")
        if line == "":
            break
        lines.append(line)

    body = " ".join(lines)
    if not body.strip():
        print("\n  ⚠️  No body entered — skipping.")
        return

    print_triage_result(
        label="Your Email", sender=sender,
        subject=subject, body=body,
        show_email=False,
    )


def show_checklist():
    print()
    divider("═")
    print("  📋  PHISHING RED FLAG CHECKLIST  —  Pause → Verify → Report")
    divider("═")
    print()

    items = [
        ("Sender",      "Does the sender's domain match the brand they claim to be?"),
        ("Sender",      "Is the Reply-To address different from the From address?"),
        ("Urgency",     "Is there unusual time pressure or a countdown-style threat?"),
        ("Fear",        "Does it threaten legal action, account closure, or arrest?"),
        ("Greed",       "Does it promise an unexpected prize, lottery win, or reward?"),
        ("Authority",   "Does it impersonate a CEO, IT department, bank, or government?"),
        ("Credentials", "Does it ask for a password, OTP, card number, or SSN via email?"),
        ("Links",       "Are there HTTP links, raw IP addresses, or URL shorteners?"),
        ("Links",       "Does the displayed link text match the actual URL destination?"),
        ("Secrecy",     "Does it tell you to keep it secret or skip normal procedures?"),
        ("Attachments", "Is there an unexpected attachment (.exe, .zip, .docm, .lnk)?"),
        ("Other",       "Is the greeting generic ('Dear Customer') rather than your name?"),
        ("Other",       "Are there QR codes asking you to scan to 'secure your account'?"),
    ]

    current_cat = None
    for i, (cat, question) in enumerate(items, start=1):
        if cat != current_cat:
            print(f"  ── {cat.upper()} " + "─" * (44 - len(cat)))
            current_cat = cat
        print(f"   [{i:>2}]  {question}")

    print()
    divider()
    print("  🔴  HIGH RISK → items 1, 7, 8, 10, 11")
    print("  🟡  MEDIUM RISK → all others")
    print()
    print("  0 flags        → Safe.       Close the ticket.")
    print("  1–2 soft flags → Suspicious. Warn user. Verify via phone.")
    print("  Any hard flag  → Malicious.  Block domain. Escalate now.")
    print()
    divider("═")


# --- Entry point ---

def main():
    print()
    divider("═")
    print("  🎣  PHISHING EMAIL TRIAGE ANALYZER")
    print("      Cybersecurity Awareness Training Tool")
    divider("═")
    print()

    while True:
        divider()
        print("  MENU:")
        print()
        print("    [1]  Run 3 built-in sample emails")
        print("    [2]  Analyse my own email")
        print("    [3]  View Red Flag Checklist")
        print("    [4]  Quit")
        print()

        choice = input("  Enter 1–4: ").strip()

        if choice == "1":
            run_sample_emails()
        elif choice == "2":
            manual_analysis()
        elif choice == "3":
            show_checklist()
        elif choice == "4":
            print()
            print("  🙏  Thank you for using DecodeLabs Phishing Awareness Tool. Remember: Pause → Verify → Report.")
            print()
            break
        else:
            print("\n  ⚠️  Please enter 1, 2, 3, or 4.")
            continue

        print()
        if input("  Back to menu? (y / n): ").strip().lower() not in ("y", "yes"):
            print()
            print("  🙏  Thank you for using DecodeLabs Phishing Awareness Tool. Remember: Pause → Verify → Report.")
            print()
            break


if __name__ == "__main__":
    main()