#!/usr/bin/env python3
"""AST-based auth patching for MCP server.py files."""
import ast, sys, os, re

AUTH_IMPORT = '''import sys, os
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access
'''

def patch_file(path: str):
    with open(path) as f:
        source = f.read()
    
    if 'check_access(api_key)' in source:
        return False, "already patched"
    
    lines = source.splitlines()
    tree = ast.parse(source)
    
    tool_funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute) and dec.func.attr == 'tool':
                        tool_funcs.append(node)
                elif isinstance(dec, ast.Attribute) and dec.attr == 'tool':
                    tool_funcs.append(node)
    
    if not tool_funcs:
        return False, "no tool functions found"
    
    # Gather modifications
    sig_replacements = {}  # line_idx -> new_line
    auth_inserts = {}      # line_idx -> [lines]
    
    for func in tool_funcs:
        has_api_key = any(arg.arg == 'api_key' for arg in func.args.args + func.args.kwonlyargs)
        
        if not has_api_key:
            # Find signature end line
            sig_line = func.lineno - 1  # 0-based
            for i in range(sig_line, min(len(lines), sig_line + 20)):
                if '-> str:' in lines[i] and ')' in lines[i]:
                    old = lines[i]
                    # Replace tier param with api_key param if present
                    if 'tier: str' in old:
                        new = old.replace('tier: str = "free"', 'api_key: str = ""').replace('tier: str = "pro"', 'api_key: str = ""').replace('tier: str', 'api_key: str')
                    else:
                        new = old.replace(') -> str:', ', api_key: str = "") -> str:')
                    sig_replacements[i] = new
                    break
                elif '-> str:' in lines[i+1] if i+1 < len(lines) else False:
                    # multi-line signature ending next line
                    pass
        
        # Find insert point after docstring
        insert_line = None
        if isinstance(func.body[0], ast.Expr) and isinstance(func.body[0].value, ast.Constant) and isinstance(func.body[0].value.value, str):
            insert_line = func.body[0].end_lineno  # 1-based -> we'll use as 0-based index for insertion AFTER
        else:
            insert_line = func.body[0].lineno - 1
        
        if insert_line is not None:
            idx = insert_line  # insert AFTER this 0-based line? end_lineno is 1-based, so idx = end_lineno means after that line
            # Actually end_lineno is 1-based line number of last line of docstring
            # We want to insert after it, so index = end_lineno (since list[idx] is the next line)
            idx = insert_line
            indent = '    '
            if idx < len(lines):
                indent = lines[idx][:len(lines[idx]) - len(lines[idx].lstrip())] or '    '
            auth_lines = [
                indent + 'allowed, msg, tier = check_access(api_key)',
                indent + 'if not allowed:',
                indent + '    return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})'
            ]
            auth_inserts[idx] = auth_lines
    
    # Add import
    has_import = 'check_access' in source
    if not has_import:
        last_import = 0
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                last_import = i + 1
        auth_inserts[last_import] = AUTH_IMPORT.strip().split('\n')
    
    # Apply in reverse line order
    all_ops = []
    for k, v in sig_replacements.items():
        all_ops.append((k, 'replace', v))
    for k, v in auth_inserts.items():
        all_ops.append((k, 'insert', v))
    
    all_ops.sort(key=lambda x: (-x[0], 0 if x[1] == 'replace' else 1))
    
    for line_idx, op, content in all_ops:
        if op == 'replace':
            lines[line_idx] = content
        else:
            for c in reversed(content):
                lines.insert(line_idx, c)
    
    with open(path, "w") as f:
        f.write('\n'.join(lines))
    
    return True, f"patched {len(tool_funcs)} tools"

if __name__ == "__main__":
    for path in sys.argv[1:]:
        ok, msg = patch_file(path)
        print(f"{path}: {msg}")
