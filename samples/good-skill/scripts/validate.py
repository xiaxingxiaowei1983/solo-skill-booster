#!/usr/bin/env python3
"""Good Skill 校验脚本 — 演示完整Skill包应有的脚本质量"""

import sys
import os
import re
from pathlib import Path


def validate_frontmatter(skill_dir):
    skill_path = Path(skill_dir) / "SKILL.md"
    if not skill_path.exists():
        return False, "SKILL.md not found"
    content = skill_path.read_text(encoding="utf-8")
    if not content.startswith("---"):
        return False, "Missing YAML frontmatter"
    parts = content.split("---", 2)
    if len(parts) < 3:
        return False, "Frontmatter not properly closed"
    if "name:" not in parts[1]:
        return False, "Missing name field"
    if "description:" not in parts[1]:
        return False, "Missing description field"
    return True, "Frontmatter valid"


def validate_no_input_blocking(skill_dir):
    scripts_dir = Path(skill_dir) / "scripts"
    if not scripts_dir.exists():
        return True, "No scripts directory"
    for py_file in scripts_dir.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        if re.search(r"\binput\s*\(", content):
            return False, f"{py_file.name} contains input()"
    return True, "No input() blocking"


def validate_no_hardcoded_secrets(skill_dir):
    secret_patterns = [
        r'api[_-]?key\s*=\s*["\'][^"\']{8,}',
        r'password\s*=\s*["\'][^"\']{4,}',
        r'secret\s*=\s*["\'][^"\']{8,}',
        r'token\s*=\s*["\'][^"\']{8,}',
    ]
    for root, _, files in os.walk(skill_dir):
        for f in files:
            if f.endswith((".py", ".js", ".ts", ".md")):
                fpath = Path(root) / f
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for pattern in secret_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return False, f"{fpath.relative_to(skill_dir)}: potential secret"
    return True, "No hardcoded secrets"


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate.py <skill_dir>")
        sys.exit(2)
    skill_dir = sys.argv[1]
    checks = [
        ("Frontmatter", validate_frontmatter),
        ("No input() blocking", validate_no_input_blocking),
        ("No hardcoded secrets", validate_no_hardcoded_secrets),
    ]
    all_pass = True
    for name, check_fn in checks:
        passed, msg = check_fn(skill_dir)
        status = "PASS" if passed else "FAIL"
        print(f"  {status}: {name} — {msg}")
        if not passed:
            all_pass = False
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
