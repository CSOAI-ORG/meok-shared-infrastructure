#!/usr/bin/env python3
"""
MEOK MCP Key Delivery Automation
=================================
Processes pending API key deliveries from Stripe webhook.
Sends welcome emails with API keys, setup instructions, and upgrade paths.

Usage:
    python3 mcp-key-delivery.py --once          # Process pending keys once
    python3 mcp-key-delivery.py --daemon        # Run as daemon (checks every 60s)
    python3 mcp-key-delivery.py --dry-run       # Preview emails without sending
    python3 mcp-key-delivery.py --resend-all    # Re-send all undelivered keys

Requires:
    - RESEND_API_KEY in environment (or use --smtp for custom SMTP)
    - Or: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD in environment
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

PENDING_FILE = os.path.expanduser("~/.meok/pending_key_delivery.jsonl")
DELIVERED_FILE = os.path.expanduser("~/.meok/key_delivery_log.jsonl")

# Email configuration
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.resend.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "resend")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", RESEND_API_KEY)
FROM_EMAIL = os.environ.get("FROM_EMAIL", "mcp@meok.ai")
FROM_NAME = os.environ.get("FROM_NAME", "MEOK AI Labs")

# Pricing page URLs
PRICING_URL = "https://meok.ai/pricing"
DOCS_URL = "https://docs.meok.ai/mcp"
SUPPORT_EMAIL = "support@meok.ai"


def load_pending_keys() -> list:
    """Load all undelivered keys from pending file."""
    if not os.path.exists(PENDING_FILE):
        return []

    pending = []
    with open(PENDING_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if not entry.get("delivered", False):
                    pending.append(entry)
            except json.JSONDecodeError:
                continue

    return pending


def mark_delivered(entry: dict, success: bool = True, error: str = None):
    """Mark a key as delivered and log the result."""
    # Update pending file
    entries = []
    with open(PENDING_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if (e.get("api_key") == entry.get("api_key") and
                    e.get("email") == entry.get("email") and
                    not e.get("delivered", False)):
                    e["delivered"] = success
                    e["delivered_at"] = datetime.utcnow().isoformat()
                    if error:
                        e["delivery_error"] = error
                entries.append(e)
            except json.JSONDecodeError:
                entries.append(line)

    with open(PENDING_FILE, "w") as f:
        for e in entries:
            if isinstance(e, dict):
                f.write(json.dumps(e) + "\n")
            else:
                f.write(str(e) + "\n")

    # Log to delivery log
    log_entry = {
        "email": entry.get("email"),
        "tier": entry.get("tier"),
        "api_key_prefix": entry.get("api_key", "")[:12] + "...",
        "delivered": success,
        "timestamp": datetime.utcnow().isoformat(),
    }
    if error:
        log_entry["error"] = error

    os.makedirs(os.path.dirname(DELIVERED_FILE), exist_ok=True)
    with open(DELIVERED_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def generate_email_html(entry: dict) -> str:
    """Generate the welcome email HTML."""
    api_key = entry.get("api_key", "")
    tier = entry.get("tier", "starter").upper()
    email = entry.get("email", "there")
    customer_name = entry.get("customer_name", email.split("@")[0])

    # Tier-specific content
    tier_limits = {
        "starter": {"daily": "100", "frameworks": "1", "price": "£29/mo"},
        "professional": {"daily": "1,000", "frameworks": "5", "price": "£299/mo"},
        "enterprise": {"daily": "Unlimited", "frameworks": "Unlimited", "price": "£999/mo"},
    }

    limits = tier_limits.get(entry.get("tier", "starter"), tier_limits["starter"])

    # MCP packages for this tier
    if entry.get("tier") == "enterprise":
        mcp_list = "All 219+ MCP servers (EU AI Act, GDPR, DORA, NIS2, SOC2, ISO 42001, HIPAA, PCI DSS, and more)"
    elif entry.get("tier") == "professional":
        mcp_list = "Top 30 compliance MCPs (EU AI Act, GDPR, DORA, NIS2, SOC2, ISO 42001, and more)"
    else:
        mcp_list = "EU AI Act Compliance MCP (starter package)"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header p {{ margin: 10px 0 0; opacity: 0.9; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }}
        .key-box {{ background: #1a1a2e; color: #00ff88; padding: 15px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 14px; word-break: break-all; margin: 20px 0; }}
        .tier-badge {{ display: inline-block; background: #00ff88; color: #1a1a2e; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; }}
        .limits {{ background: white; padding: 20px; border-radius: 6px; margin: 20px 0; }}
        .limits table {{ width: 100%; border-collapse: collapse; }}
        .limits td {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        .limits td:last-child {{ text-align: right; font-weight: bold; }}
        .cta {{ display: inline-block; background: #00ff88; color: #1a1a2e; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; margin: 10px 5px; }}
        .cta.secondary {{ background: #1a1a2e; color: white; }}
        .footer {{ text-align: center; margin-top: 30px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to MEOK AI Labs</h1>
        <p>Your AI compliance toolkit is ready</p>
    </div>
    <div class="content">
        <p>Hi {customer_name},</p>
        <p>Thank you for subscribing to <strong>MEOK MCP {tier}</strong>. Your API key is ready:</p>

        <div class="key-box">
            {api_key}
        </div>

        <p><span class="tier-badge">{tier} TIER</span></p>

        <div class="limits">
            <h3 style="margin-top: 0;">Your Plan Limits</h3>
            <table>
                <tr><td>Daily API Calls</td><td>{limits['daily']}</td></tr>
                <tr><td>Compliance Frameworks</td><td>{limits['frameworks']}</td></tr>
                <tr><td>Monthly Price</td><td>{limits['price']}</td></tr>
            </table>
        </div>

        <h3>What's Included</h3>
        <p>{mcp_list}</p>

        <h3>Quick Start</h3>
        <ol>
            <li><strong>Install:</strong> <code>pip install meok-eu-ai-act-compliance-mcp</code></li>
            <li><strong>Configure:</strong> Set <code>MEOK_API_KEY={api_key[:20]}...</code> in your environment</li>
            <li><strong>Run:</strong> Start your MCP client and connect</li>
        </ol>

        <p style="text-align: center; margin: 30px 0;">
            <a href="{DOCS_URL}" class="cta">Read Documentation</a>
            <a href="{PRICING_URL}" class="cta secondary">Upgrade Plan</a>
        </p>

        <p>Need help? Reply to this email or contact us at <a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a></p>
    </div>
    <div class="footer">
        <p>MEOK AI Labs | Sovereign AI Compliance | https://meok.ai</p>
        <p>This is an automated message. Please do not reply directly.</p>
    </div>
</body>
</html>"""

    return html


def generate_email_text(entry: dict) -> str:
    """Generate plain text version of the email."""
    api_key = entry.get("api_key", "")
    tier = entry.get("tier", "starter").upper()
    email = entry.get("email", "there")
    customer_name = entry.get("customer_name", email.split("@")[0])

    text = f"""Hi {customer_name},

Thank you for subscribing to MEOK MCP {tier}. Your API key is ready:

API KEY: {api_key}

TIER: {tier}

Quick Start:
1. Install: pip install meok-eu-ai-act-compliance-mcp
2. Configure: Set MEOK_API_KEY={api_key[:20]}... in your environment
3. Run: Start your MCP client and connect

Documentation: {DOCS_URL}
Pricing: {PRICING_URL}
Support: {SUPPORT_EMAIL}

---
MEOK AI Labs | Sovereign AI Compliance | https://meok.ai
"""
    return text


def send_via_resend(to_email: str, subject: str, html: str, text: str) -> dict:
    """Send email via Resend API."""
    if not RESEND_API_KEY:
        return {"error": "RESEND_API_KEY not set"}

    payload = json.dumps({
        "from": f"{FROM_NAME} <{FROM_EMAIL}>",
        "to": [to_email],
        "subject": subject,
        "html": html,
        "text": text,
    }).encode()

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"status": "success", "id": json.loads(r.read()).get("id")}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}


def send_via_smtp(to_email: str, subject: str, html: str, text: str) -> dict:
    """Send email via SMTP."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
        msg["To"] = to_email

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        return {"status": "success"}
    except Exception as e:
        return {"error": str(e)}


def send_email(entry: dict, dry_run: bool = False) -> dict:
    """Send welcome email for a pending key."""
    subject = f"Your MEOK MCP {entry.get('tier', 'starter').upper()} API Key is Ready"
    html = generate_email_html(entry)
    text = generate_email_text(entry)

    if dry_run:
        return {"status": "dry-run", "to": entry.get("email"), "subject": subject}

    # Try Resend first, fall back to SMTP
    if RESEND_API_KEY:
        result = send_via_resend(entry.get("email"), subject, html, text)
    else:
        result = send_via_smtp(entry.get("email"), subject, html, text)

    return result


def process_pending(dry_run: bool = False, resend_all: bool = False) -> dict:
    """Process all pending key deliveries."""
    pending = load_pending_keys()

    if resend_all:
        # Load all keys ever (including delivered ones)
        all_entries = []
        if os.path.exists(PENDING_FILE):
            with open(PENDING_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        all_entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        pending = all_entries

    if not pending:
        print("   No pending keys found.")
        return {"status": "no-pending", "count": 0, "total": 0, "sent": 0, "failed": 0}

    results = {
        "total": len(pending),
        "sent": 0,
        "failed": 0,
        "dry_run": dry_run,
        "details": [],
    }

    for entry in pending:
        print(f"  Sending to {entry.get('email')} (tier: {entry.get('tier')})...", end=" ")

        result = send_email(entry, dry_run=dry_run)
        status = result.get("status", "error")

        if status in ("success", "dry-run"):
            print(f"✅ {status}")
            results["sent"] += 1
            if not dry_run:
                mark_delivered(entry, success=True)
        else:
            print(f"❌ {result.get('error', 'unknown')}")
            results["failed"] += 1
            if not dry_run:
                mark_delivered(entry, success=False, error=result.get("error"))

        results["details"].append({
            "email": entry.get("email"),
            "tier": entry.get("tier"),
            "status": status,
            "error": result.get("error"),
        })

        # Rate limiting
        if not dry_run:
            time.sleep(1)

    return results


def run_daemon(interval: int = 60, dry_run: bool = False):
    """Run as daemon, checking for pending keys every N seconds."""
    print(f"🔄 Key Delivery Daemon started (interval: {interval}s, dry-run: {dry_run})")
    print(f"   Monitoring: {PENDING_FILE}")
    print()

    while True:
        pending = load_pending_keys()
        if pending:
            print(f"[{datetime.utcnow().isoformat()}] Found {len(pending)} pending key(s)")
            results = process_pending(dry_run=dry_run)
            print(f"   Sent: {results['sent']}, Failed: {results['failed']}")
        else:
            print(f"[{datetime.utcnow().isoformat()}] No pending keys")

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="MEOK MCP Key Delivery")
    parser.add_argument("--once", action="store_true", help="Process pending keys once")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    parser.add_argument("--interval", type=int, default=60, help="Daemon check interval (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without sending")
    parser.add_argument("--resend-all", action="store_true", help="Re-send all undelivered keys")

    args = parser.parse_args()

    if not args.once and not args.daemon:
        # Default: process once
        args.once = True

    if args.daemon:
        run_daemon(interval=args.interval, dry_run=args.dry_run)
    elif args.once:
        print("📧 MEOK MCP Key Delivery")
        print(f"   Pending file: {PENDING_FILE}")
        print(f"   Dry run: {args.dry_run}")
        print(f"   Resend all: {args.resend_all}")
        print()

        results = process_pending(dry_run=args.dry_run, resend_all=args.resend_all)

        print(f"\n📊 Results:")
        print(f"   Total: {results['total']}")
        print(f"   Sent: {results['sent']}")
        print(f"   Failed: {results['failed']}")


if __name__ == "__main__":
    main()
