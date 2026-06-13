#!/usr/bin/env python3
"""
MEOK Labs — Key Delivery Daemon
================================
Sends API keys to customers after Stripe payment.
Reads pending_key_delivery.jsonl, sends welcome email via Resend,
marks as delivered.

Environment variables needed:
  RESEND_API_KEY — from https://resend.com
  MEOK_FROM_EMAIL — sender address (default: hello@meok.ai)

Deploy: python key_delivery_daemon.py
"""

import json
import os
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [KEY_DELIVERY] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.expanduser("~/.meok/key_delivery.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

PENDING_FILE = os.path.expanduser("~/.meok/pending_key_delivery.jsonl")
DELIVERED_FILE = os.path.expanduser("~/.meok/delivered_keys.jsonl")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
MEOK_FROM_EMAIL = os.environ.get("MEOK_FROM_EMAIL", "hello@meok.ai")
MEOK_BASE_URL = os.environ.get("MEOK_BASE_URL", "https://try.meok.ai")

WELCOME_TEMPLATE = """Hello {name},

Your MEOK AI Labs API key is ready!

Tier: {tier}
API Key: {api_key}

Quick start:

1. Install any MEOK MCP server:
   pip install {mcp_package}

2. Add your API key to the config:
   export MEOK_API_KEY={api_key}

3. Start using your compliance tools immediately.

Your dashboard: {base_url}/dashboard

If you need help, reply to this email or visit {base_url}/support

Welcome aboard,
The MEOK AI Labs Team
"""

PRO_TEMPLATE = """Hello {name},

Your MEOK AI Labs Pro API key is ready!

Tier: {tier}
API Key: {api_key}

As a Pro subscriber, you have access to:

- Unlimited compliance checks
- HMAC-signed attestations (auditor-verifiable)
- Priority support
- All {mcp_count} governance MCP servers

Quick start:

1. Install the governance pack:
   npx meok-setup --pack governance

2. Set your API key:
   export MEOK_API_KEY={api_key}

3. Run your first attestation:
   eu-ai-act-compliance-mcp --attest --entity "Your Company" --scope "high-risk"

Your dashboard: {base_url}/dashboard

Questions? Reply anytime.

Welcome aboard,
The MEOK AI Labs Team
"""

TIER_MCP_COUNT = {
    "starter": 5,
    "professional": 38,
    "enterprise": 38,
}

TIER_MCP_PACKAGE = {
    "starter": "meok-core-pack",
    "professional": "meok-governance-pack",
    "enterprise": "meok-governance-pack",
}


def send_via_resend(to_email: str, subject: str, body: str) -> bool:
    if not RESEND_API_KEY:
        logger.error("RESEND_API_KEY not set — cannot send email. Set this environment variable.")
        return False

    import urllib.request
    import urllib.error

    url = "https://api.resend.com/emails"
    payload = json.dumps({
        "from": f"MEOK AI Labs <{MEOK_FROM_EMAIL}>",
        "to": [to_email],
        "subject": subject,
        "text": body,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {RESEND_API_KEY}")

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                logger.info(f"Email sent to {to_email} via Resend")
                return True
            else:
                logger.error(f"Resend returned status {resp.status}")
                return False
    except urllib.error.HTTPError as e:
        logger.error(f"Resend HTTP error: {e.code} {e.reason}")
        return False
    except Exception as e:
        logger.error(f"Resend error: {e}")
        return False


def send_via_smtp(to_email: str, subject: str, body: str) -> bool:
    smtp_host = os.environ.get("SMTP_HOST", "smtp.resend.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", MEOK_FROM_EMAIL)
    smtp_pass = os.environ.get("SMTP_PASS", RESEND_API_KEY)

    if not smtp_pass:
        logger.error("No SMTP credentials — cannot send email")
        return False

    msg = MIMEMultipart()
    msg["From"] = f"MEOK AI Labs <{MEOK_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(MEOK_FROM_EMAIL, to_email, msg.as_string())
        logger.info(f"Email sent to {to_email} via SMTP")
        return True
    except Exception as e:
        logger.error(f"SMTP error: {e}")
        return False


def send_welcome_email(email: str, api_key: str, tier: str, customer_name: str = "") -> bool:
    name = customer_name or email.split("@")[0]
    mcp_package = TIER_MCP_PACKAGE.get(tier, "meok-core-pack")
    mcp_count = TIER_MCP_COUNT.get(tier, 5)

    if tier == "professional" or tier == "enterprise":
        body = PRO_TEMPLATE.format(
            name=name,
            tier=tier,
            api_key=api_key,
            mcp_count=mcp_count,
            mcp_package=mcp_package,
            base_url=MEOK_BASE_URL,
        )
        subject = f"Your MEOK {tier.title()} API Key is Ready — {mcp_count} Governance MCPs Unlocked"
    else:
        body = WELCOME_TEMPLATE.format(
            name=name,
            tier=tier,
            api_key=api_key,
            mcp_package=mcp_package,
            base_url=MEOK_BASE_URL,
        )
        subject = f"Your MEOK API Key is Ready — Welcome to AI Compliance"

    success = False
    if RESEND_API_KEY:
        success = send_via_resend(email, subject, body)
        if not success:
            logger.info("Resend failed, trying SMTP fallback")
            success = send_via_smtp(email, subject, body)
    else:
        success = send_via_smtp(email, subject, body)

    return success


def process_pending_keys():
    if not os.path.exists(PENDING_FILE):
        return 0

    delivered = 0
    remaining = []

    with open(PENDING_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if entry.get("delivered"):
                delivered += 1
                continue

            email = entry.get("email", "")
            api_key = entry.get("api_key", "")
            tier = entry.get("tier", "starter")
            customer_name = entry.get("customer_name", "")

            if not email or not api_key:
                logger.warning(f"Skipping incomplete entry: {entry}")
                remaining.append(entry)
                continue

            logger.info(f"Sending key to {email} (tier: {tier})...")
            success = send_welcome_email(email, api_key, tier, customer_name)

            if success:
                entry["delivered"] = True
                entry["delivered_at"] = datetime.utcnow().isoformat()
                delivered += 1

                with open(DELIVERED_FILE, "a") as df:
                    df.write(json.dumps(entry) + "\n")

                logger.info(f"DELIVERED key to {email}")
            else:
                logger.warning(f"FAILED to deliver key to {email} — will retry")
                entry["delivery_attempts"] = entry.get("delivery_attempts", 0) + 1
                entry["last_attempt"] = datetime.utcnow().isoformat()

                if entry["delivery_attempts"] >= 5:
                    logger.error(f"5 delivery attempts failed for {email} — giving up")
                    entry["delivered"] = False
                    entry["failed_permanent"] = True

                remaining.append(entry)

    with open(PENDING_FILE, "w") as f:
        for entry in remaining:
            f.write(json.dumps(entry) + "\n")

    return delivered


def main():
    logger.info("=" * 60)
    logger.info("MEOK Key Delivery Daemon starting")
    logger.info(f"RESEND_API_KEY: {'SET' if RESEND_API_KEY else 'NOT SET'}")
    logger.info(f"MEOK_FROM_EMAIL: {MEOK_FROM_EMAIL}")
    logger.info(f"Pending file: {PENDING_FILE}")
    logger.info("=" * 60)

    if not RESEND_API_KEY:
        logger.error("RESEND_API_KEY not set — key delivery will FAIL.")
        logger.error("Get one at https://resend.com and set RESEND_API_KEY env var")
        logger.error("Continuing in dry-run mode...")

    while True:
        try:
            count = process_pending_keys()
            if count > 0:
                logger.info(f"Processed {count} key(s)")
        except Exception as e:
            logger.error(f"Error processing keys: {e}", exc_info=True)

        time.sleep(30)


if __name__ == "__main__":
    main()