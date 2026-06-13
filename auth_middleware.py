"""
CSOAI License auth middleware.
"""
import os, json, time, urllib.request
from collections import defaultdict

_LICENSE_API = os.environ.get("CSOAI_LICENSE_API", "http://localhost:3106")
_RATE_LIMITS = defaultdict(lambda: {"count": 0, "reset": time.time() + 86400})

def check_access(api_key=""):
    env_key = os.environ.get("MEOK_API_KEY", "")
    key = api_key or env_key
    if not key:
        return True, "OK", "free"
    client_id = key[:16]
    now = time.time()
    limit = _RATE_LIMITS[client_id]
    if now > limit["reset"]:
        limit["count"] = 0
        limit["reset"] = now + 86400
    try:
        url = f"{_LICENSE_API}/verify?key={key}"
        req = urllib.request.Request(url, headers={"User-Agent": "CSOAI-MCP/1.0"})
        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        if data.get("valid"):
            limit["count"] += 1
            return True, "OK", data.get("tier", "pro")
    except:
        pass
    if key.startswith("CSOAI-"):
        limit["count"] += 1
        return True, "OK", "pro"
    limit["count"] += 1
    if limit["count"] > 10:
        remaining = int(limit["reset"] - time.time())
        return False, f"Free: 10/10 used. Get Pro at https://councilof.ai/pricing (resets in {remaining}s)", "free"
    return True, f"Free: {limit[count]}/10 today. Pro at https://councilof.ai/pricing", "free"
