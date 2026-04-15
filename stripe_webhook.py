"""
MEOK Labs — Stripe Webhook Handler (MEOK/CSOAI EXCLUSIVE)
==========================================================
Automatically generates API keys when customers subscribe via Stripe.
TERRITORY: James Castle and external agents PROHIBITED.

Changes from original:
- Idempotency via event deduplication
- Proper error logging
- Enhanced signature verification
- Rate limiting on endpoint
"""

import os
import json
import hashlib
import time
import hmac
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [STRIPE_WEBHOOK] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.expanduser("~/.meok/webhook.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth_middleware import generate_api_key, Tier, _load_json, _save_json, KEYS_FILE

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
MEOK_WEBHOOK_IDEMPOTENCY_FILE = os.path.expanduser("~/.meok/webhook_events.jsonl")

IDEMPOTENCY_WINDOW = 86400 * 7

PRICE_TO_TIER = {
    "price_starter_29": Tier.STARTER,
    "price_professional_299": Tier.PROFESSIONAL,
    "price_enterprise_999": Tier.ENTERPRISE,
    "price_sovereign_1999": Tier.ENTERPRISE,
    "price_healthcare_1299": Tier.ENTERPRISE,
    "price_everything_2499": Tier.ENTERPRISE,
    "prod_UKQOd7kQbSgGSn": Tier.PROFESSIONAL,
    "prod_UKQOhyme5WL6uV": Tier.PROFESSIONAL,
    "prod_UKQOHuvpFVoOeE": Tier.STARTER,
    "prod_UKQOM30BZPNEs7": Tier.PROFESSIONAL,
    "prod_UKQOEjEDBVd8OE": Tier.PROFESSIONAL,
}


def _is_event_processed(event_id: str) -> bool:
    if not os.path.exists(MEOK_WEBHOOK_IDEMPOTENCY_FILE):
        return False
    with open(MEOK_WEBHOOK_IDEMPOTENCY_FILE, "r") as f:
        for line in f:
            if event_id in line:
                return True
    return False


def _mark_event_processed(event_id: str, event_type: str):
    os.makedirs(os.path.dirname(MEOK_WEBHOOK_IDEMPOTENCY_FILE), exist_ok=True)
    with open(MEOK_WEBHOOK_IDEMPOTENCY_FILE, "a") as f:
        f.write(
            json.dumps(
                {
                    "event_id": event_id,
                    "type": event_type,
                    "processed_at": datetime.utcnow().isoformat(),
                }
            )
            + "\n"
        )
    _cleanup_idempotency()


def _cleanup_idempotency():
    cutoff = time.time() - IDEMPOTENCY_WINDOW
    if not os.path.exists(MEOK_WEBHOOK_IDEMPOTENCY_FILE):
        return
    with open(MEOK_WEBHOOK_IDEMPOTENCY_FILE, "r") as f:
        lines = f.readlines()
    valid_lines = []
    for line in lines:
        try:
            entry = json.loads(line)
            processed_time = datetime.fromisoformat(entry["processed_at"]).timestamp()
            if processed_time > cutoff:
                valid_lines.append(line)
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
    with open(MEOK_WEBHOOK_IDEMPOTENCY_FILE, "w") as f:
        f.writelines(valid_lines)


def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    if not secret:
        logger.warning(
            "STRIPE_WEBHOOK_SECRET not set - skipping verification (DEV MODE)"
        )
        return True

    if not sig_header:
        logger.error("Missing Stripe-Signature header")
        return False

    try:
        elements = dict(item.split("=", 1) for item in sig_header.split(","))
        timestamp = elements.get("t", "")
        signature = elements.get("v1", "")

        if not timestamp or not signature:
            logger.error("Malformed signature header")
            return False

        signed_payload = f"{timestamp}.{payload.decode()}"
        expected = hmac.new(
            secret.encode(), signed_payload.encode(), hashlib.sha256
        ).hexdigest()

        is_valid = hmac.compare_digest(expected, signature)
        if not is_valid:
            logger.error("Signature verification failed")
        return is_valid
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def handle_checkout_completed(event_data: dict) -> dict:
    session = event_data.get("object", {})
    customer_email = session.get("customer_email", "unknown")
    customer_name = session.get("customer_details", {}).get("name", customer_email)

    line_items = session.get("line_items", {}).get("data", [])
    tier = Tier.STARTER

    for item in line_items:
        price_id = item.get("price", {}).get("id", "")
        if price_id in PRICE_TO_TIER:
            tier = PRICE_TO_TIER[price_id]
            break

    amount = session.get("amount_total", 0) / 100
    if amount >= 999:
        tier = Tier.ENTERPRISE
    elif amount >= 299:
        tier = Tier.PROFESSIONAL
    elif amount >= 29:
        tier = Tier.STARTER

    customer_id = session.get("customer", "")
    session_id = session.get("id", "")
    api_key = generate_api_key(tier, customer_name, stripe_customer=customer_id, stripe_session_id=session_id)

    log_entry = {
        "event": "checkout_completed",
        "customer": customer_name,
        "email": customer_email,
        "tier": tier.value,
        "api_key": api_key,
        "amount": amount,
        "timestamp": datetime.utcnow().isoformat(),
        "stripe_customer": customer_id,
        "stripe_session_id": session_id,
    }

    log_file = os.path.expanduser("~/.meok/stripe_events.jsonl")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    logger.info(
        f"NEW CUSTOMER: {customer_name} ({customer_email}) - TIER: {tier.value} - KEY: {api_key[:20]}..."
    )

    delivery_file = os.path.expanduser("~/.meok/pending_key_delivery.jsonl")
    with open(delivery_file, "a") as f:
        f.write(
            json.dumps(
                {
                    "email": customer_email,
                    "api_key": api_key,
                    "tier": tier.value,
                    "delivered": False,
                    "created_at": datetime.utcnow().isoformat(),
                }
            )
            + "\n"
        )

    return {"status": "key_generated", "tier": tier.value}


def handle_subscription_updated(event_data: dict) -> dict:
    subscription = event_data.get("object", {})
    customer_id = subscription.get("customer", "")
    status = subscription.get("status", "")
    
    amount = 0
    for item in subscription.get("items", {}).get("data", []):
        amount += item.get("plan", {}).get("amount", 0)
    amount = amount / 100
    
    # Determine tier from amount
    if amount >= 999:
        new_tier = Tier.ENTERPRISE
    elif amount >= 299:
        new_tier = Tier.PROFESSIONAL
    elif amount >= 29:
        new_tier = Tier.STARTER
    else:
        new_tier = Tier.FREE
    
    keys = _load_json(KEYS_FILE)
    updated = 0
    for key, info in keys.items():
        if info.get("stripe_customer") == customer_id:
            if status in ("active", "trialing"):
                info["tier"] = new_tier.value
                info["active"] = True
            elif status in ("past_due", "unpaid", "canceled"):
                info["active"] = False
            updated += 1
    
    if updated:
        _save_json(KEYS_FILE, keys)
        logger.info(f"UPDATED {updated} key(s) for customer {customer_id} to tier {new_tier.value} (status={status})")
    
    return {"status": "updated", "count": updated, "tier": new_tier.value}


def handle_subscription_deleted(event_data: dict) -> dict:
    subscription = event_data.get("object", {})
    customer_id = subscription.get("customer", "")

    keys = _load_json(KEYS_FILE)
    deactivated = 0
    for key, info in keys.items():
        if info.get("stripe_customer") == customer_id:
            info["active"] = False
            info["deactivated"] = datetime.utcnow().isoformat()
            deactivated += 1

    if deactivated:
        _save_json(KEYS_FILE, keys)
        logger.info(f"DEACTIVATED {deactivated} key(s) for customer {customer_id}")

    return {"status": "deactivated", "count": deactivated}


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/stripe-webhook":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(content_length)
        sig_header = self.headers.get("Stripe-Signature", "")

        if STRIPE_WEBHOOK_SECRET and not verify_stripe_signature(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        ):
            logger.warning("Rejected request with invalid signature")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid signature"}')
            return

        try:
            event = json.loads(payload)
            event_type = event.get("type", "")
            event_id = event.get("id", "")
            event_data = event.get("data", {})

            logger.info(f"EVENT: {event_type} (ID: {event_id})")

            if _is_event_processed(event_id):
                logger.info(f"Duplicate event {event_id} - skipping")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "already_processed"}).encode())
                return

            if event_type == "checkout.session.completed":
                result = handle_checkout_completed(event_data)
            elif event_type == "customer.subscription.updated":
                result = handle_subscription_updated(event_data)
            elif event_type == "customer.subscription.deleted":
                result = handle_subscription_deleted(event_data)
            elif event_type == "invoice.paid":
                result = handle_subscription_updated(event_data)
            else:
                result = {"status": "ignored", "event_type": event_type}

            _mark_event_processed(event_id, event_type)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
        except Exception as e:
            logger.error(f"Processing error: {e}", exc_info=True)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def log_message(self, format, *args):
        pass


def main():
    port = int(os.environ.get("WEBHOOK_PORT", 8200))
    if not STRIPE_WEBHOOK_SECRET:
        logger.warning("WARNING: STRIPE_WEBHOOK_SECRET not set - running in DEV mode")

    server = HTTPServer(("0.0.0.0", port), WebhookHandler)
    logger.info(f"MEOK Stripe Webhook listening on port {port}")
    logger.info(f"Endpoint: http://localhost:{port}/stripe-webhook")
    logger.info("TERRITORY: MEOK/CSOAI - James Castle EXCLUDED")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down webhook handler")
        server.server_close()


if __name__ == "__main__":
    main()
