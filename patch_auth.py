#!/usr/bin/env python3
"""Patch auth checks into MCP server.py files automatically."""
import re, sys, os

AUTH_IMPORT = '''import sys, os
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access
import json
'''

AUTH_CHECK = '''    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
'''

def patch_file(path: str):
    with open(path) as f:
        text = f.read()
    
    # Don't double-patch
    if 'check_access(api_key)' in text:
        return False, "already patched"
    
    # Add import after first import block
    if 'from auth_middleware import' not in text and 'import auth_middleware' not in text:
        # Find a good spot after imports
        lines = text.splitlines()
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("import ") or line.startswith("from "):
                insert_idx = i + 1
        lines.insert(insert_idx, AUTH_IMPORT.strip())
        text = "\n".join(lines)
    
    # Inject auth check into each async def tool function that has @mcp.tool above it
    pattern = re.compile(r'(@mcp\.tool\([^)]*\)\n)(async def \w+\([^)]*\) -> str:\n)(    )"""', re.MULTILINE)
    
    def replacer(m):
        # Check if api_key param exists; if not, we need to add it
        func_sig = m.group(2)
        if 'api_key' not in func_sig:
            # Add api_key: str = "" before ) -> str
            func_sig = func_sig.replace(') -> str:', ', api_key: str = "") -> str:')
        return m.group(1) + func_sig + m.group(3) + '"""' + m.group(0).split('"""')[-1].replace(m.group(3) + '"""', m.group(3) + '"""\n' + m.group(3) + AUTH_CHECK.strip().replace('\n', '\n' + m.group(3)) + '\n' + m.group(3), 1)
    
    # Actually let's do a simpler approach: find each @mcp.tool and the following function body start
    lines = text.splitlines()
    new_lines = []
    i = 0
    while i < len(lines):
        new_lines.append(lines[i])
        if re.match(r'\s*@mcp\.tool', lines[i]):
            # Look ahead for async def
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith('async def '):
                new_lines.append(lines[j])
                j += 1
            if j < len(lines):
                # Check if api_key in signature
                if 'api_key' not in lines[j]:
                    lines[j] = lines[j].replace(') -> str:', ', api_key: str = "") -> str:')
                new_lines.append(lines[j])
                j += 1
                # Find docstring end
                if j < len(lines) and lines[j].strip().startswith('"""'):
                    new_lines.append(lines[j])
                    j += 1
                    while j < len(lines) and '"""' not in lines[j]:
                        new_lines.append(lines[j])
                        j += 1
                    if j < len(lines):
                        new_lines.append(lines[j])
                        j += 1
                # Insert auth check with same indent as next line
                indent = '    '
                if j < len(lines):
                    indent = lines[j][:len(lines[j]) - len(lines[j].lstrip())] or '    '
                auth_lines = [indent + l for l in AUTH_CHECK.strip().split('\n')]
                new_lines.extend(auth_lines)
                i = j - 1
        i += 1
    
    with open(path, "w") as f:
        f.write("\n".join(new_lines))
    return True, "patched"

if __name__ == "__main__":
    for path in sys.argv[1:]:
        ok, msg = patch_file(path)
        print(f"{path}: {msg}")
