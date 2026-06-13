import sys, re
for path in sys.argv[1:]:
    with open(path) as f:
        text = f.read()
    # Fix the bad replacements
    text = re.sub(r'\( *, api_key:', '(api_key:', text)
    text = re.sub(r',\s*, api_key:', ', api_key:', text)
    text = re.sub(r'\n\s*, api_key:', '\n    api_key:', text)
    # Specifically fix lines that start with comma
    lines = text.splitlines()
    new_lines = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith(', api_key:'):
            line = line.replace(', api_key:', 'api_key:')
        new_lines.append(line)
    with open(path, "w") as f:
        f.write('\n'.join(new_lines))
    print(f"{path}: fixed")
