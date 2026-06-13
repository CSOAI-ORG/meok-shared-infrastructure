#!/usr/bin/env python3
"""Replace _check_rate_limit with real auth check in MCP servers."""
import re, sys

REPLACEMENT = '''def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> str | None:
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from auth_middleware import check_access
    allowed, msg, actual_tier = check_access("")
    if not allowed:
        return msg
    return None
'''

def patch_file(path: str):
    with open(path) as f:
        text = f.read()
    
    # Pattern to find _check_rate_limit function definition through its body
    pattern = r'def _check_rate_limit\([^)]*\):\s*\n(?:    .*\n)*'
    
    if not re.search(r'def _check_rate_limit', text):
        return False, "no _check_rate_limit found"
    
    if 'check_access' in text:
        return False, "already has check_access"
    
    # Replace the function
    new_text = re.sub(pattern, REPLACEMENT, text)
    
    if new_text == text:
        # Fallback: more aggressive replacement
        lines = text.splitlines()
        start = None
        end = None
        for i, line in enumerate(lines):
            if re.match(r'def _check_rate_limit\(', line):
                start = i
            elif start is not None and end is None and line.strip() and not line.startswith(' ') and not line.startswith('\t'):
                end = i
        if start is not None:
            if end is None:
                end = len(lines)
            new_lines = lines[:start] + REPLACEMENT.strip().split('\n') + lines[end:]
            new_text = '\n'.join(new_lines)
        else:
            return False, "could not locate function boundaries"
    
    with open(path, "w") as f:
        f.write(new_text)
    return True, "patched"

if __name__ == "__main__":
    for path in sys.argv[1:]:
        ok, msg = patch_file(path)
        print(f"{path}: {msg}")
