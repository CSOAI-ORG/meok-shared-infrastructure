"""
Stripe Tier Checker — Real-time subscription verification for MEOK MCP servers.
Checks customer's Stripe subscription to determine their access tier.

Usage:
    tier = check_stripe_tier(customer_email="nick@example.com")
    # Returns: "free", "starter", "professional", "enterprise"
"""

import os
import json
import time
import hashlib

STRIPE_KEY = os.environ.get("STRIPE_SECRET_KEY", os.environ.get("MEOK_STRIPE_KEY", ""))

# Price ID → Tier mapping (from actual Stripe products)
PRICE_TIER_MAP = {
    # Individual MCPs (£29/mo = starter)
    "price_1TLlXs": "starter",
    "price_1TLlXt": "starter",
    "price_1TLlXu": "starter",
    "price_1TLlXv": "starter",
    "price_1TLlXw": "starter",
    # Trinity Bundle (£79-299/mo = professional)
    # Full Suite (£999/mo = enterprise)
    # Everything Pack (£2499/mo = enterprise)
}

# Cache to avoid hammering Stripe on every call
_tier_cache = {}
_cache_ttl = 300  # 5 minutes

def check_stripe_tier(customer_email: str = "", api_key: str = "") -> str:
    """Check Stripe subscription tier for a customer."""
    
    if not STRIPE_KEY:
        return "free"  # No Stripe key = dev mode
    
    # Check cache first
    cache_key = hashlib.sha256(f"{customer_email}{api_key}".encode()).hexdigest()[:16]
    if cache_key in _tier_cache:
        entry = _tier_cache[cache_key]
        if time.time() - entry["time"] < _cache_ttl:
            return entry["tier"]
    
    try:
        import urllib.request
        
        # Search for customer by email
        if customer_email:
            url = f"https://api.stripe.com/v1/customers/search?query=email:'{customer_email}'"
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {STRIPE_KEY}")
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read())
            
            customers = data.get("data", [])
            if not customers:
                _tier_cache[cache_key] = {"tier": "free", "time": time.time()}
                return "free"
            
            customer_id = customers[0]["id"]
            
            # Get active subscriptions
            url = f"https://api.stripe.com/v1/subscriptions?customer={customer_id}&status=active"
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {STRIPE_KEY}")
            resp = urllib.request.urlopen(req, timeout=5)
            subs = json.loads(resp.read())
            
            if not subs.get("data"):
                _tier_cache[cache_key] = {"tier": "free", "time": time.time()}
                return "free"
            
            # Determine highest tier from subscriptions
            highest = "starter"
            for sub in subs["data"]:
                for item in sub.get("items", {}).get("data", []):
                    amount = item.get("price", {}).get("unit_amount", 0)
                    if amount >= 99900:  # £999+
                        highest = "enterprise"
                    elif amount >= 29900:  # £299+
                        highest = "professional"
                    elif amount >= 2900:  # £29+
                        if highest not in ("professional", "enterprise"):
                            highest = "starter"
            
            _tier_cache[cache_key] = {"tier": highest, "time": time.time()}
            return highest
    
    except Exception:
        pass
    
    return "free"

def get_tier_limits(tier: str) -> dict:
    """Get rate limits for a tier."""
    return {
        "free": {"calls_per_day": 10, "frameworks": 1, "audit_trail": False},
        "starter": {"calls_per_day": 100, "frameworks": 1, "audit_trail": False},
        "professional": {"calls_per_day": 1000, "frameworks": 5, "audit_trail": True},
        "enterprise": {"calls_per_day": -1, "frameworks": -1, "audit_trail": True},
    }.get(tier, {"calls_per_day": 10, "frameworks": 1, "audit_trail": False})
