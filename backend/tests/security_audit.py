import os
import re

def audit_frontend_secrets():
    base_dir = r"D:\Adamas Hackathon\CyberShield_AI_Final_Integration\frontend\src"
    pattern = re.compile(r"(?i)(api[_-]?key|secret|private[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]")
    found = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(('.ts', '.tsx', '.js', '.json', '.html')):
                path = os.path.join(root, f)
                with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                    for idx, line in enumerate(fh, 1):
                        if pattern.search(line):
                            found.append((path, idx, line.strip()))
    return found

def audit_gitignore():
    path = r"D:\Adamas Hackathon\CyberShield_AI_Final_Integration\.gitignore"
    if not os.path.exists(path):
        return False, []
    with open(path, 'r', encoding='utf-8') as fh:
        content = fh.read()
    checks = {
        ".env": ".env" in content,
        "*.db": "*.db" in content or "cyber_shield.db" in content,
        "node_modules": "node_modules" in content,
        "__pycache__": "__pycache__" in content
    }
    return True, checks

if __name__ == "__main__":
    fe_secrets = audit_frontend_secrets()
    print(f"Frontend hardcoded secrets count: {len(fe_secrets)}")
    for p, l, text in fe_secrets:
        print(f"  {p}:{l} -> {text[:30]}...")

    gi_ok, checks = audit_gitignore()
    print(f".gitignore present: {gi_ok}, rules: {checks}")

