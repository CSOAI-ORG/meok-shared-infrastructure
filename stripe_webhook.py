"""
MEOK Labs — Stripe Webhook Handler
Automatically generates API keys when customers subscribe via Stripe.
Deploy as a simple Flask/FastAPI endpoint on your server.

Flow:
1. Customer clicks Stripe payment link (£29/mo, £299/mo, £999/mo)
2. Stripe fires webhook to this endpoint
3. This script creates an API key in ~/.meok/api_keys.json
4. Sends confirmation email with API key + setup instructions

Deploy: python stripe_webhook.py (runs on port 8200)
Configure Stripe webhook: https://dashboard.stripe.com/webhooks
  → Endpoint: https://your-server.com/stripe-webhook
  → Events: checkout.session.completed, customer.subscription.deleted
"""

import os
import json
import hashlib
import time
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler

# Import the auth middleware
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth_middleware import generate_api_key, Tier, _load_json, _save_json, KEYS_FILE

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# Map Stripe price IDs to tiers
# UPDATE THESE with your actual Stripe price IDs
PRICE_TO_TIER = {
    # Individual servers at £29/mo
    "price_starter_29": Tier.STARTER,
    # Professional at £299/mo
    "price_professional_299": Tier.PROFESSIONAL,
    # Enterprise at £999/mo
    "price_enterprise_999": Tier.ENTERPRISE,
    # Bundles
    "price_sovereign_1999": Tier.ENTERPRISE,
    "price_healthcare_1299": Tier.ENTERPRISE,
    "price_everything_2499": Tier.ENTERPRISE,
}


def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify Stripe webhook signature."""
    if not secret:
        return True  # Skip verification in dev mode
    
    try:
        elements = dict(item.split("=", 1) for item in sig_header.split(","))
        timestamp = elements.get("t", "")
        signature = elements.get("v1", "")
        
        signed_payload = f"{timestamp}.{payload.decode()}"
        expected = hmac.new(
            secret.encode(), signed_payload.encode(), hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def handle_checkout_completed(event_data: dict) -> dict:
    """Handle successful checkout — generate API key."""
    session = event_data.get("object", {})
    customer_email = session.get("customer_email", "unknown")
    customer_name = session.get("customer_details", {}).get("name", customer_email)
    
    # Determine tier from line items
    line_items = session.get("line_items", {}).get("data", [])
    tier = Tier.STARTER  # default
    
    for item in line_items:
        price_id = item.get("price", {}).get("id", "")
        if price_id in PRICE_TO_TIER:
            tier = PRICE_TO_TIER[price_id]
            break
    
    # Check amount as fallback
    amount = session.get("amount_total", 0) / 100  # Convert from pence
    if amount >= 999:
        tier = Tier.ENTERPRISE
    elif amount >= 299:
        tier = Tier.PROFESSIONAL
    elif amount >= 29:
        tier = Tier.STARTER
    
    # Generate API key
    api_key = generate_api_key(tier, customer_name)
    
    # Log the event
    log_entry = {
        "event": "checkout_completed",
        "customer": customer_name,
        "email": customer_email,
        "tier": tier.value,
        "api_key": api_key,
        "amount": amount,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stripe_session_id": session.get("id", ""),
    }
    
    log_file = os.path.expanduser("~/.meok/stripe_events.jsonl")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"  NEW CUSTOMER: {customer_name} ({customer_email})")
    print(f"  TIER: {tier.value}")
    print(f"  KEY: {api_key}")
    
    # TODO: Send email with API key and setup instructions
    # For now, save to a "pending delivery" file
    delivery_file = os.path.expanduser("~/.meok/pending_key_delivery.jsonl")
    with open(delivery_file, "a") as f:
        f.write(json.dumps({
            "email": customer_email,
            "api_key": api_key,
            "tier": tier.value,
            "delivered": False,
        }) + "\n")
    
    return {"status": "key_generated", "tier": tier.value}


def handle_subscription_deleted(event_data: dict) -> dict:
    """Handle subscription cancellation — deactivate API key."""
    subscription = event_data.get("object", {})
    customer_id = subscription.get("customer", "")
    
    # Find and deactivate matching keys
    keys = _load_json(KEYS_FILE)
    deactivated = 0
    for key, info in keys.items():
        if info.get("stripe_customer") == customer_id:
            info["active"] = False
            info["deactivated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            deactivated += 1
    
    if deactivated:
        _save_json(KEYS_FILE, keys)
        print(f"  DEACTIVATED {deactivated} key(s) for customer {customer_id}")
    
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
        
        # Verify signature
        if STRIPE_WEBHOOK_SECRET and not verify_stripe_signature(payload, sig_header, STRIPE_WEBHOOK_SECRET):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid signature"}')
            return
        
        try:
            event = json.loads(payload)
            event_type = event.get("type", "")
            event_data = event.get("data", {})
            
            print(f"\n  STRIPE EVENT: {event_type}")
            
            if event_type == "checkout.session.completed":
                result = handle_checkout_completed(event_data)
            elif event_type == "customer.subscription.deleted":
                result = handle_subscription_deleted(event_data)
            else:
                result = {"status": "ignored", "event_type": event_type}
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        except Exception as e:
            print(f"  ERROR: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress default logging


def main():
    port = int(os.environ.get("WEBHOOK_PORT", 8200))
    server = HTTPServer(("0.0.0.0", port), WebhookHandler)
    print(f"MEOK Stripe Webhook listening on port {port}")
    print(f"Endpoint: http://localhost:{port}/stripe-webhook")
    print(f"Configure in Stripe Dashboard → Webhooks")
    print(f"Events: checkout.session.completed, customer.subscription.deleted")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down webhook handler")
        server.server_close()


if __name__ == "__main__":
    main()
