# MEOK Shared Infrastructure

Shared modules for all MEOK AI Labs MCP servers.

## auth_middleware.py
Stripe-to-MCP tier authentication. Every server imports this.

## stripe_webhook.py
Handles Stripe webhook events to provision/revoke API keys.

## Usage
```python
from auth_middleware import get_tier_from_api_key, Tier, TIER_LIMITS
tier = get_tier_from_api_key(api_key)
```

---
**MEOK AI Labs** | meok.ai
