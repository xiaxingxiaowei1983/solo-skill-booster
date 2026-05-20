#!/usr/bin/env python3
"""SOLO Skill 合规校验脚本 — 覆盖8类内容检查 + Shannon熵安全扫描 + 注入模式检测"""

import sys
import os
import re
import math

try:
    import yaml
except ImportError:
    yaml = None


def shannon_entropy(s):
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


INJECTION_PATTERNS = [
    (r"\beval\s*\(", "eval 动态执行", "high", "code_injection"),
    (r"\bexec\s*\(", "exec 动态执行", "high", "code_injection"),
    (r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True", "shell=True 调用", "high", "command_injection"),
    (r"\bos\.system\s*\(", "os.system 调用", "high", "command_injection"),
    (r"(?i)\bf['\"](?:[^'\"]*?)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b", "f-string SQL 查询", "high", "sql_injection"),
    (r"(?i)(?:prompt|system_prompt|user_prompt|messages?)\s*=\s*f['\"][^'\"]*\{(?:user|input|query|request|data)", "用户输入直接拼入 LLM prompt", "high", "prompt_injection"),
    (r"\.innerHTML\s*=\s*(?!['\"]\s*$)[^;]+", "innerHTML 赋值（XSS 风险）", "medium", "xss"),
    (r"\brequests\.(?:get|post|put|patch|delete)\s*\([^)]*(?:\bvar\b|\bdata\b|\brequest\b|\bparams?\b|\burl\b)", "用户可控 URL 的 HTTP 请求（SSRF 风险）", "medium", "ssrf"),
    (r"\bopen\s*\([^)]*(?:\brequest\b|\bparams?\b|\bquery\b|\bform\b|\buser\b|\bargv\b)", "用户可控路径的文件操作（路径遍历风险）", "high", "path_traversal"),
]

PLACEHOLDER_VALUES = [
    "your-api-key", "sk-xxx", "<YOUR_TOKEN>", "example-token",
    "dummy-secret", "your_key_here", "replace_me", "xxx",
    "placeholder", "INSERT_KEY", "YOUR_API_KEY", "changeme",
    "todo", "fixme", "dummy", "fake", "sample", "test123",
    "sk_test_", "pk_test_",
]

_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|/\*|\*|;|rem\b|@rem\b)", re.IGNORECASE)
_MARKDOWN_CODE_FENCE = re.compile(r"^\s*```")
_PLACEHOLDER_PATTERN = re.compile(
    r"(?i)(?:example|placeholder|changeme|xxx+|your[_-]?key[_-]?here|"
    r"insert[_-]?here|replace[_-]?me|todo|fixme|dummy|fake|sample|test123|"
    r"sk_test_|pk_test_)"
)


def check_frontmatter(skill_dir):
    errors = []
    skill_path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_path):
        return [{"check": "SKILL.md存在", "status": "FAIL", "detail": "SKILL.md文件不存在"}]

    with open(skill_path, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.startswith("---"):
        errors.append({"check": "frontmatter格式", "status": "FAIL", "detail": "缺少YAML frontmatter"})
        return errors

    parts = content.split("---", 2)
    if len(parts) < 3:
        errors.append({"check": "frontmatter格式", "status": "FAIL", "detail": "frontmatter未正确关闭"})
        return errors

    if yaml:
        try:
            meta = yaml.safe_load(parts[1])
        except yaml.YAMLError as e:
            errors.append({"check": "frontmatter解析", "status": "FAIL", "detail": f"YAML解析错误: {e}"})
            return errors

        if not meta.get("name"):
            errors.append({"check": "name字段", "status": "FAIL", "detail": "frontmatter缺少name字段"})
        if not meta.get("description"):
            errors.append({"check": "description字段", "status": "FAIL", "detail": "frontmatter缺少description字段"})
    else:
        if "name:" not in parts[1]:
            errors.append({"check": "name字段", "status": "FAIL", "detail": "frontmatter缺少name字段"})
        if "description:" not in parts[1]:
            errors.append({"check": "description字段", "status": "FAIL", "detail": "frontmatter缺少description字段"})

    return errors


def check_scripts(skill_dir):
    errors = []
    scripts_dir = os.path.join(skill_dir, "scripts")
    if not os.path.exists(scripts_dir):
        return []

    for root, _, files in os.walk(scripts_dir):
        for fname in files:
            if not fname.endswith((".py", ".js", ".ts", ".sh")):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, skill_dir)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            has_input_call = bool(re.search(r'(?<![\'"\w])input\s*\(', content))
            if has_input_call:
                errors.append({
                    "check": "脚本交互阻塞",
                    "status": "FAIL",
                    "detail": f"{rel_path} 包含input()，会导致Agent卡死"
                })
            errors.extend(_check_sensitive_in_file(content, rel_path))
            has_try = "try" in content or "catch" in content or "except" in content
            if not has_try:
                errors.append({
                    "check": "脚本错误处理",
                    "status": "WARN",
                    "detail": f"{rel_path} 无try-catch错误处理"
                })
            has_sys_exit = "sys.exit" in content or "process.exit" in content
            if not has_sys_exit:
                errors.append({
                    "check": "脚本退出码",
                    "status": "WARN",
                    "detail": f"{rel_path} 无退出码定义"
                })
    return errors


def _check_sensitive_in_file(content, rel_path):
    errors = []
    sensitive_patterns = [
        (r'password\s*=\s*["\']([^"\']+)["\']', "硬编码密码"),
        (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "硬编码 API Key"),
        (r'token\s*=\s*["\']([^"\']+)["\']', "硬编码 Token"),
        (r'secret\s*=\s*["\']([^"\']+)["\']', "硬编码密钥"),
        (r'private[_-]?key\s*=\s*["\']([^"\']+)["\']', "硬编码私钥"),
    ]
    for pattern, issue_type in sensitive_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            value = match.group(0)
            if any(p in value.lower() for p in PLACEHOLDER_VALUES):
                continue
            errors.append({
                "check": issue_type,
                "status": "FAIL",
                "detail": f"{rel_path} 包含{issue_type}"
            })
    return errors


def check_entropy_scan(skill_dir):
    errors = []
    for root, _, files in os.walk(skill_dir):
        if any(skip in root for skip in [".git", "node_modules", "__pycache__", ".venv", "dist", "build", "samples"]):
            continue
        for fname in files:
            if not fname.endswith((".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml", ".env")):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, skill_dir)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            in_code_block = False
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                if _MARKDOWN_CODE_FENCE.match(stripped):
                    in_code_block = not in_code_block
                    continue
                if _COMMENT_LINE_RE.match(stripped) or in_code_block or _PLACEHOLDER_PATTERN.search(stripped):
                    continue
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    continue

                for token_match in re.finditer(r"""['"]([^'"]{16,})['\"]""", line):
                    token = token_match.group(1)
                    if re.match(r'^[\\^$.*+\[\]{}()|?]+$', token):
                        continue
                    if token.startswith('\\') or token.startswith('^') or token.startswith('(?)'):
                        continue
                    ent = shannon_entropy(token)
                    if ent > 4.5:
                        severity = "FAIL" if ent > 5.0 else "WARN"
                        errors.append({
                            "check": "高熵字符串（可能是密钥）",
                            "status": severity,
                            "detail": f"{rel_path}:{line_num} 熵值={ent:.2f}，字符串={token[:8]}****"
                        })
    return errors


def check_injection_patterns(skill_dir):
    errors = []
    for root, _, files in os.walk(skill_dir):
        if any(skip in root for skip in [".git", "node_modules", "__pycache__", ".venv", "dist", "build", "references", "examples"]):
            continue
        for fname in files:
            if not fname.endswith((".py", ".js", ".ts", ".sh")):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, skill_dir)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            in_code_block = False
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                if _MARKDOWN_CODE_FENCE.match(stripped):
                    in_code_block = not in_code_block
                    continue
                if _COMMENT_LINE_RE.match(stripped) or in_code_block or _PLACEHOLDER_PATTERN.search(stripped):
                    continue

                for regex_pattern, issue_type, base_sev, injection_type in INJECTION_PATTERNS:
                    if re.search(regex_pattern, line):
                        severity = "FAIL" if base_sev == "high" else "WARN"
                        errors.append({
                            "check": f"{issue_type}（{injection_type}）",
                            "status": severity,
                            "detail": f"{rel_path}:{line_num} 检测到{issue_type}"
                        })
    return errors


def check_structure(skill_dir):
    errors = []
    skill_path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_path):
        return errors

    with open(skill_path, "r", encoding="utf-8") as f:
        content = f.read()

    body = content.split("---", 2)[-1] if content.startswith("---") else content

    checks = [
        ("使用场景", "使用场景" in body or "适合" in body, "WARN"),
        ("使用示例", "示例" in body or "example" in body.lower(), "WARN"),
        ("不做什么", "不做什么" in body or "不适合" in body or "边界" in body, "WARN"),
        ("输出格式", "输出格式" in body or "输出样例" in body or "输出" in body, "WARN"),
        ("依赖说明", "依赖" in body or "requirements" in body.lower(), "WARN"),
        ("运行方式", "触发" in body or "运行" in body or "使用步骤" in body, "WARN"),
    ]

    for name, found, level in checks:
        if not found:
            errors.append({
                "check": f"内容完整性: {name}",
                "status": level,
                "detail": f"SKILL.md中未找到'{name}'相关内容"
            })

    return errors


def check_dependencies(skill_dir):
    errors = []
    has_scripts = os.path.exists(os.path.join(skill_dir, "scripts"))
    has_req_py = os.path.exists(os.path.join(skill_dir, "scripts", "requirements.txt"))
    has_pkg_json = os.path.exists(os.path.join(skill_dir, "package.json"))
    has_req_root = os.path.exists(os.path.join(skill_dir, "requirements.txt"))

    if has_scripts and not has_req_py and not has_req_root and not has_pkg_json:
        errors.append({
            "check": "依赖声明",
            "status": "WARN",
            "detail": "有scripts/目录但无requirements.txt或package.json"
        })
    return errors


def check_skill_type(skill_dir):
    info = {"type": "unknown", "signals": []}
    if os.path.exists(os.path.join(skill_dir, "scripts")):
        info["type"] = "tool"
        info["signals"].append("scripts/")
    if os.path.exists(os.path.join(skill_dir, "references")):
        if info["type"] == "tool":
            info["type"] = "mixed"
        else:
            info["type"] = "knowledge"
        info["signals"].append("references/")
    if os.path.exists(os.path.join(skill_dir, "templates")) or os.path.exists(os.path.join(skill_dir, "assets")):
        if info["type"] in ("tool", "knowledge"):
            info["type"] = "mixed"
        else:
            info["type"] = "template"
        info["signals"].append("templates/ or assets/")
    if os.path.exists(os.path.join(skill_dir, "workflow")) or os.path.exists(os.path.join(skill_dir, "roles")):
        info["type"] = "orchestrator"
        info["signals"].append("workflow/ or roles/")
    if not info["signals"]:
        info["type"] = "prompt"
        info["signals"].append("SKILL.md only")
    return info


def check_ai_laziness(skill_dir):
    findings = []
    skill_path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_path):
        return [{"check": "SKILL.md存在", "status": "FAIL", "detail": "SKILL.md不存在"}]

    with open(skill_path, "r", encoding="utf-8") as f:
        content = f.read()

    lazy_patterns = [
        (r"\binput\s*\(", "input()交互阻塞", "P0", "Agent运行时会卡死"),
        (r"TODO|FIXME|HACK|XXX", "TODO/FIXME残留", "P1", "未完成的占位符"),
        (r"placeholder|占位符|待补充|待完善", "占位符内容未替换", "P1", "AI生成的占位符未替换为真实内容"),
        (r"示例\d|example\d|sample\d", "示例编号未替换", "P2", "示例编号应替换为真实内容"),
        (r"你的.*在这里|your.*here|insert.*here", "模板占位符未替换", "P1", "模板占位符应替换为实际值"),
    ]

    for pattern, name, level, reason in lazy_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({
                "check": f"AI偷懒: {name}",
                "status": "WARN" if level != "P0" else "FAIL",
                "detail": f"发现{len(matches)}处 — {reason}",
            })

    scripts_dir = os.path.join(skill_dir, "scripts")
    if os.path.isdir(scripts_dir):
        for fname in os.listdir(scripts_dir):
            if fname.endswith(".py"):
                fpath = os.path.join(scripts_dir, fname)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    script_content = f.read()
                for pattern, name, level, reason in lazy_patterns:
                    matches = re.findall(pattern, script_content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "check": f"AI偷懒: {name}",
                            "status": "WARN" if level != "P0" else "FAIL",
                            "detail": f"scripts/{fname}: 发现{len(matches)}处 — {reason}",
                        })

    if not findings:
        findings.append({"check": "AI偷懒模式检测", "status": "PASS", "detail": "未发现AI偷懒模式"})

    return findings


def check_terminology_consistency(skill_dir):
    findings = []
    skill_path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_path):
        return [{"check": "SKILL.md存在", "status": "FAIL", "detail": "SKILL.md不存在"}]

    with open(skill_path, "r", encoding="utf-8") as f:
        content = f.read()

    deprecated_terms = [
        ("评审官", "提分官"),
        ("裁判", "提分官"),
        ("打分器", "提分官"),
        ("检查器", "提分官"),
        ("审核工具", "提分官"),
    ]

    for old_term, new_term in deprecated_terms:
        if old_term in content:
            findings.append({
                "check": f"术语一致性: '{old_term}'",
                "status": "WARN",
                "detail": f"应使用'{new_term}'替代'{old_term}'",
            })

    if not findings:
        findings.append({"check": "术语一致性", "status": "PASS", "detail": "术语使用一致"})

    return findings


def validate_skill(skill_dir):
    all_errors = []

    skill_type_info = check_skill_type(skill_dir)
    print(f"  Skill类型: {skill_type_info['type']} (信号: {', '.join(skill_type_info['signals'])})")

    all_errors.extend(check_frontmatter(skill_dir))
    all_errors.extend(check_scripts(skill_dir))
    all_errors.extend(check_structure(skill_dir))
    all_errors.extend(check_dependencies(skill_dir))
    all_errors.extend(check_ai_laziness(skill_dir))
    all_errors.extend(check_terminology_consistency(skill_dir))

    print("  正在执行 Shannon 熵扫描...")
    entropy_errors = check_entropy_scan(skill_dir)
    all_errors.extend(entropy_errors)

    print("  正在执行注入模式检测...")
    injection_errors = check_injection_patterns(skill_dir)
    all_errors.extend(injection_errors)

    fail_count = sum(1 for e in all_errors if e["status"] == "FAIL")
    warn_count = sum(1 for e in all_errors if e["status"] == "WARN")

    print(f"\n{'='*60}")
    print(f"SOLO Skill 合规校验: {skill_dir}")
    print(f"{'='*60}\n")

    if not all_errors:
        print("PASS — 所有检查项通过")
        return 0

    for e in all_errors:
        icon = "FAIL" if e["status"] == "FAIL" else "WARN"
        print(f"  [{icon}] {e['check']}: {e['detail']}")

    print(f"\n结果: {fail_count} FAIL, {warn_count} WARN")

    if fail_count > 0:
        print("结论: FAIL — 存在必须修复的问题")
        return 1
    else:
        print("结论: CONDITIONAL — 存在建议修复的问题")
        return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python validate_skill.py <skill目录路径>")
        print("  退出码: 0=PASS, 1=FAIL, 2=参数错误")
        sys.exit(2)

    skill_dir = sys.argv[1]
    if not os.path.isdir(skill_dir):
        print(f"错误: {skill_dir} 不是有效目录")
        sys.exit(2)

    sys.exit(validate_skill(skill_dir))
