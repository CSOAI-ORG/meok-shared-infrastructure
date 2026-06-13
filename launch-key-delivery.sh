#!/bin/bash
# MCP Key Delivery — Daemon Launcher
# Uses SMTP credentials from environment
# Usage: ./launch-key-delivery.sh [--resend-all]

set -e

echo "📧 Launching MCP Key Delivery Daemon..."
echo "   SMTP: $SMTP_HOST:$SMTP_PORT ($SMTP_USER)"
echo "   Pending file: ~/.meok/pending_key_delivery.jsonl"
echo "   Check interval: 60 seconds"
echo ""

# Export configuration
export SMTP_HOST="${SMTP_HOST:-mail.privateemail.com}"
export SMTP_PORT="${SMTP_PORT:-587}"
export SMTP_USER="${SMTP_USER:-nicholas@csoai.org}"
export SMTP_PASSWORD="${SMTP_PASSWORD:-}"
export FROM_EMAIL="${FROM_EMAIL:-nicholas@csoai.org}"
export FROM_NAME="${FROM_NAME:-MEOK AI Labs}"

# Check if SMTP credentials are set
if [ -z "$SMTP_PASSWORD" ]; then
    echo "❌ SMTP_PASSWORD not set — daemon will run in dry-run mode"
    echo "   Set SMTP_PASSWORD in your environment to enable sending"
    DRY_RUN="--dry-run"
else
    DRY_RUN=""
fi

# Run the daemon
if [ "$1" = "--resend-all" ]; then
    echo "✅ Resend ALL undelivered keys"
    python3 ~/clawd/meok-labs-engine/shared/mcp-key-delivery.py --daemon --interval 60 $DRY_RUN --resend-all
else
    echo "🔄 Processing new pending keys only"
    python3 ~/clawd/meok-labs-engine/shared/mcp-key-delivery.py --daemon --interval 60 $DRY_RUN
fi
