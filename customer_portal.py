#!/usr/bin/env python3
"""
MEOK Labs — Customer Portal API
================================
Serves /api/customer-portal for subscribers to manage their API keys,
view usage, and upgrade/cancel subscriptions.

Deploy: python customer_portal.py (runs on port 8300)
"""

import json
import os
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PORTAL] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

sys_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, sys_path)
from auth_middleware import _load_json, KEYS_FILE, Tier, MEOK_DIR

PORTAL_DIR = os.path.join(MEOK_DIR, "portal_sessions")
os.makedirs(PORTAL_DIR, exist_ok=True)


class PortalHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "https://meok.ai")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "https://meok.ai")
        self.end_headers()
        self.wfile.write(html.encode())

    def _get_api_key(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer meok_"):
            return auth[7:]
        return ""

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://meok.ai")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api/customer-portal":
            self._handle_portal()
        elif path == "/api/customer-portal/usage":
            self._handle_usage(params)
        elif path == "/api/customer-portal/keys":
            self._handle_keys()
        elif path == "/api/health":
            self._send_json({"status": "healthy", "service": "meok-customer-portal"})
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/customer-portal/rotate-key":
            self._handle_rotate_key()
        elif path == "/api/customer-portal/upgrade":
            self._handle_upgrade()
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/customer-portal/cancel":
            self._handle_cancel()
        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_portal(self):
        api_key = self._get_api_key()
        if not api_key:
            self._send_html(PORTAL_HTML)
            return

        keys = _load_json(KEYS_FILE)
        key_info = keys.get(api_key)
        if not key_info:
            self._send_json({"error": "Invalid API key"}, 401)
            return

        self._send_json({
            "customer": {
                "name": key_info.get("name", "Valued Customer"),
                "email": key_info.get("email", ""),
                "tier": key_info.get("tier", "free"),
                "created": key_info.get("created", ""),
                "active": key_info.get("active", True),
            },
            "subscription": {
                "tier": key_info.get("tier", "free"),
                "status": "active" if key_info.get("active") else "cancelled",
                "started": key_info.get("created", ""),
                "stripe_customer": key_info.get("stripe_customer", ""),
            },
            "actions": {
                "upgrade_url": "https://meok.ai/pricing",
                "docs_url": "https://meok.ai/docs",
                "support_url": "https://meok.ai/support",
            }
        })

    def _handle_usage(self, params):
        api_key = self._get_api_key()
        if not api_key:
            self._send_json({"error": "API key required"}, 401)
            return

        usage_file = os.path.join(MEOK_DIR, "usage.json")
        if os.path.exists(usage_file):
            usage_data = json.loads(Path(usage_file).read_text())
            key_usage = usage_data.get(api_key, {})
            self._send_json({
                "api_key": api_key[:20] + "...",
                "calls_today": key_usage.get("calls_today", 0),
                "calls_this_month": key_usage.get("calls_this_month", 0),
                "tier_limit": key_usage.get("tier_limit", 10),
                "remaining_today": max(0, key_usage.get("tier_limit", 10) - key_usage.get("calls_today", 0)),
            })
        else:
            self._send_json({
                "api_key": api_key[:20] + "...",
                "calls_today": 0,
                "calls_this_month": 0,
                "tier_limit": 10,
                "remaining_today": 10,
            })

    def _handle_keys(self):
        api_key = self._get_api_key()
        if not api_key:
            self._send_json({"error": "API key required"}, 401)
            return

        keys = _load_json(KEYS_FILE)
        key_info = keys.get(api_key, {})

        self._send_json({
            "active": key_info.get("active", True),
            "tier": key_info.get("tier", "free"),
            "created": key_info.get("created", ""),
            "last_used": key_info.get("last_used", ""),
        })

    def _handle_rotate_key(self):
        api_key = self._get_api_key()
        if not api_key:
            self._send_json({"error": "API key required"}, 401)
            return

        keys = _load_json(KEYS_FILE)
        key_info = keys.get(api_key)

        if not key_info:
            self._send_json({"error": "Invalid API key"}, 401)
            return

        from auth_middleware import generate_api_key
        import secrets
        new_key = generate_api_key(
            Tier(key_info["tier"]),
            key_info.get("name", "rotated"),
            stripe_customer=key_info.get("stripe_customer", ""),
            stripe_session_id=key_info.get("stripe_session_id", ""),
        )

        keys[api_key]["active"] = False
        keys[api_key]["rotated_to"] = new_key
        keys[api_key]["rotated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        _save_json_here(KEYS_FILE, keys)

        self._send_json({
            "message": "API key rotated successfully",
            "new_api_key": new_key,
            "old_key_deactivated": True,
        })

    def _handle_upgrade(self):
        self._send_json({
            "message": "Upgrade your subscription",
            "upgrade_url": "https://meok.ai/pricing",
            "tiers": {
                "starter": {"price": "£29/mo", "calls": 100},
                "professional": {"price": "£79/mo", "calls": 1000},
                "enterprise": {"price": "£1,499/mo", "calls": "unlimited"},
            }
        })

    def _handle_cancel(self):
        api_key = self._get_api_key()
        if not api_key:
            self._send_json({"error": "API key required"}, 401)
            return

        keys = _load_json(KEYS_FILE)
        if api_key in keys:
            keys[api_key]["active"] = False
            keys[api_key]["cancelled_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            _save_json_here(KEYS_FILE, keys)
            self._send_json({"message": "Subscription cancelled", "active": False})
        else:
            self._send_json({"error": "Invalid API key"}, 401)

    def log_message(self, format, *args):
        logger.info(format % args)


def _save_json_here(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MEOK AI Labs — Customer Portal</title>
<style>
  :root { --bg: #0a0a0a; --fg: #e5e5e5; --accent: #3b82f6; --card: #1a1a1a; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--fg); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .container { max-width: 480px; width: 100%; padding: 2rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  p { color: #999; margin-bottom: 1.5rem; }
  .card { background: var(--card); border: 1px solid #333; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
  .card h3 { font-size: 0.875rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
  .card .value { font-size: 1.25rem; font-weight: 600; }
  .actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
  .btn { padding: 0.75rem 1rem; border-radius: 6px; font-weight: 500; cursor: pointer; border: none; font-size: 0.875rem; }
  .btn-primary { background: var(--accent); color: white; }
  .btn-secondary { background: transparent; border: 1px solid #444; color: var(--fg); }
  .btn-danger { background: transparent; border: 1px solid #dc2626; color: #dc2626; }
  .footer { margin-top: 2rem; text-align: center; font-size: 0.75rem; color: #666; }
  .footer a { color: var(--accent); text-decoration: none; }
  .input-group { margin-bottom: 1rem; }
  .input-group label { display: block; font-size: 0.875rem; color: #888; margin-bottom: 0.25rem; }
  .input-group input { width: 100%; padding: 0.75rem; background: #111; border: 1px solid #333; border-radius: 6px; color: var(--fg); font-size: 0.875rem; }
</style>
</head>
<body>
<div class="container">
  <h1>MEOK Customer Portal</h1>
  <p>Manage your API key, view usage, and upgrade your subscription.</p>

  <div class="input-group">
    <label for="api-key">Enter your API key</label>
    <input type="text" id="api-key" placeholder="meok_xxxxxxxx" autocomplete="off">
  </div>

  <div class="actions">
    <button class="btn btn-primary" onclick="loadDashboard()">View Dashboard</button>
    <a href="https://meok.ai/pricing" class="btn btn-secondary">Upgrade</a>
  </div>

  <div id="dashboard" style="display:none; margin-top:1.5rem;">
    <div class="card"><h3>Tier</h3><div class="value" id="tier">—</div></div>
    <div class="card"><h3>API Key</h3><div class="value" id="key-display" style="font-family:monospace;font-size:0.8rem;">—</div></div>
    <div class="card"><h3>Calls Today</h3><div class="value" id="calls-today">—</div></div>
    <div class="actions">
      <button class="btn btn-secondary" onclick="rotateKey()">Rotate Key</button>
      <button class="btn btn-danger" onclick="cancelSub()">Cancel</button>
    </div>
  </div>

  <div class="footer">
    <a href="https://meok.ai/docs">Docs</a> · <a href="https://meok.ai/support">Support</a> · <a href="https://meok.ai/pricing">Pricing</a>
    <br>© 2026 MEOK AI Labs
  </div>
</div>
<script>
async function loadDashboard() {
  const key = document.getElementById('api-key').value.trim();
  if (!key) { alert('Please enter your API key'); return; }
  try {
    const resp = await fetch('/api/customer-portal', { headers: { 'Authorization': 'Bearer ' + key } });
    const data = await resp.json();
    if (data.error) { alert(data.error); return; }
    document.getElementById('tier').textContent = data.customer.tier.toUpperCase();
    document.getElementById('key-display').textContent = key.substring(0,12) + '...';
    document.getElementById('dashboard').style.display = 'block';
    loadUsage(key);
  } catch(e) { alert('Error: ' + e.message); }
}
async function loadUsage(key) {
  try {
    const resp = await fetch('/api/customer-portal/usage', { headers: { 'Authorization': 'Bearer ' + key } });
    const data = await resp.json();
    document.getElementById('calls-today').textContent = data.calls_today + ' / ' + data.tier_limit;
  } catch(e) { document.getElementById('calls-today').textContent = 'N/A'; }
}
async function rotateKey() {
  const key = document.getElementById('api-key').value.trim();
  if (!confirm('Rotate your API key? The old key will be deactivated.')) return;
  const resp = await fetch('/api/customer-portal/rotate-key', { method: 'POST', headers: { 'Authorization': 'Bearer ' + key } });
  const data = await resp.json();
  if (data.new_api_key) { alert('New key: ' + data.new_api_key + '\\nSave this — the old key is now deactivated.'); location.reload(); }
  else { alert('Error: ' + (data.error || 'Unknown error')); }
}
async function cancelSub() {
  if (!confirm('Cancel your subscription? This will deactivate your API key.')) return;
  const key = document.getElementById('api-key').value.trim();
  const resp = await fetch('/api/customer-portal/cancel', { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + key } });
  const data = await resp.json();
  alert(data.message || 'Cancelled');
  location.reload();
}
</script>
</body>
</html>"""


def main():
    port = int(os.environ.get("PORTAL_PORT", "8300"))
    server = HTTPServer(("0.0.0.0", port), PortalHandler)
    logger.info(f"MEOK Customer Portal running on port {port}")
    logger.info(f"Endpoints: /api/customer-portal, /api/customer-portal/usage, /api/customer-portal/keys")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down portal server")
        server.server_close()


if __name__ == "__main__":
    main()