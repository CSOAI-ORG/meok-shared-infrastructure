"""
MEOK Labs — Streamable HTTP Transport Wrapper
Deploy to: ~/clawd/meok-labs-engine/shared/http_transport.py

Adds HTTP transport to any FastMCP server for remote access.
Usage in server.py:

    # At the bottom, replace:
    #   if __name__ == "__main__": mcp.run()
    # With:
    if __name__ == "__main__":
        import sys
        sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
        from http_transport import run_server
        run_server(mcp)

This enables both stdio (default) and HTTP transport:
    python server.py              # stdio (for Claude Desktop, Cursor)
    python server.py --http       # HTTP on port 8000
    python server.py --http 3001  # HTTP on custom port
    MCP_TRANSPORT=http python server.py  # via env var
"""

import os
import sys


def run_server(mcp_instance, default_port: int = 8000):
    """Run MCP server with automatic transport selection.

    - Default: stdio (for local MCP clients)
    - --http flag or MCP_TRANSPORT=http: Streamable HTTP
    """
    transport = os.environ.get("MCP_TRANSPORT", "stdio")

    # Check for --http flag
    if "--http" in sys.argv:
        transport = "http"
        # Check for custom port after --http
        idx = sys.argv.index("--http")
        if idx + 1 < len(sys.argv) and sys.argv[idx + 1].isdigit():
            default_port = int(sys.argv[idx + 1])

    port = int(os.environ.get("MCP_PORT", str(default_port)))
    host = os.environ.get("MCP_HOST", "0.0.0.0")

    if transport == "http":
        print(f"Starting MCP server on http://{host}:{port}/mcp")
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        mcp.run()  # stdio default
