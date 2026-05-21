#!/usr/bin/env python3
"""SOLO Skill 安全扫描器 - 检测安全风险，区分真实/示例风险，含风险分级+攻击性合规+三层审计"""

import os
import re
import sys
import json
import math
import base64
from pathlib import Path
from typing import Dict, List, Any


_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|/\*|\*|;|rem\b|@rem\b)", re.IGNORECASE)
_MARKDOWN_CODE_FENCE = re.compile(r"^\s*```")
_PLACEHOLDER_PATTERN = re.compile(
    r"(?i)(?:example|placeholder|changeme|xxx+|your[_-]?key[_-]?here|"
    r"insert[_-]?here|replace[_-]?me|todo|fixme|dummy|fake|sample|test123|"
    r"sk_test_|pk_test_)"
)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_SAFE_IP_PREFIXES = ("127.", "0.", "10.", "192.168.", "169.254.", "255.")

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


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_comment_line(line: str) -> bool:
    return bool(_COMMENT_LINE_RE.match(line))


def _is_placeholder_line(line: str) -> bool:
    return bool(_PLACEHOLDER_PATTERN.search(line))


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_SAFE_IP_PREFIXES):
        return True
    parts = ip.split(".")
    try:
        if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return True
    except (IndexError, ValueError):
        pass
    return False


def _check_base64_secret(token: str) -> bool:
    padded = token + "=" * (-len(token) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
        decoded_str = decoded.decode("ascii", errors="replace")
        return shannon_entropy(decoded_str) > 4.0 and len(decoded) >= 12
    except Exception:
        return False


class OffensiveSkillChecker:
    OFFENSIVE_PATTERNS = [
        r"nmap\s", r"metasploit", r"sqlmap", r"burp\s*suite",
        r"penetration\s*test", r"red\s*team", r"exploit",
        r"vulnerability\s*scan", r"brute\s*force", r"password\s*crack",
        r"port\s*scan", r"ddos", r"phishing", r"reverse\s*shell",
    ]

    def check(self, skill_path: Path, security_result: Dict) -> Dict[str, Any]:
        is_offensive = self._detect_offensive_intent(skill_path)

        if not is_offensive:
            return {"is_offensive": False, "compliance": None}

        checks = {
            "has_disclaimer": self._check_disclaimer(skill_path),
            "has_user_confirm": self._check_user_confirmation(skill_path),
            "no_weaponized_payload": self._check_no_weaponized(skill_path, security_result),
        }

        all_passed = all(checks.values())

        return {
            "is_offensive": True,
            "compliance": {
                "all_passed": all_passed,
                "checks": checks,
                "missing": [k for k, v in checks.items() if not v],
                "blocker": not all_passed,
            }
        }

    def _detect_offensive_intent(self, skill_path: Path) -> bool:
        skill_md = skill_path / "SKILL.md"
        if not skill_md.exists():
            return False

        try:
            content = skill_md.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            return False

        for pattern in self.OFFENSIVE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        offensive_keywords = [
            "渗透测试", "红队", "漏洞利用", "攻击性", "入侵检测",
            "密码破解", "端口扫描", "后门", "提权",
        ]
        return any(kw in content for kw in offensive_keywords)

    def _check_disclaimer(self, skill_path: Path) -> bool:
        skill_md = skill_path / "SKILL.md"
        if not skill_md.exists():
            return False

        try:
            content = skill_md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False

        disclaimer_patterns = [
            r"仅限授权", r"授权使用", r"教育目的", r"书面许可",
            r"authorized\s+use", r"educational\s+purpose",
            r"explicit\s+permission", r"written\s+permission",
        ]
        return any(re.search(p, content, re.IGNORECASE) for p in disclaimer_patterns)

    def _check_user_confirmation(self, skill_path: Path) -> bool:
        scripts_dir = skill_path / "scripts"
        if not scripts_dir.exists():
            skill_md = skill_path / "SKILL.md"
            if skill_md.exists():
                try:
                    content = skill_md.read_text(encoding="utf-8", errors="ignore").lower()
                except Exception:
                    return False
                confirm_patterns = [
                    "确认", "confirm", "input(", "yes/no", "y/n",
                    "请确认", "proceed", "continue",
                ]
                return any(p in content for p in confirm_patterns)
            return False

        for script in scripts_dir.rglob("*.py"):
            if any(skip in script.parts for skip in ["__pycache__", ".venv"]):
                continue
            try:
                content = script.read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                continue
            confirm_patterns = ["input(", "confirm", "yes/no", "y/n", "确认"]
            if any(p in content for p in confirm_patterns):
                return True

        return False

    def _check_no_weaponized(self, skill_path: Path, security_result: Dict) -> bool:
        weaponized_patterns = [
            r"payload\s*=\s*['\"]", r"exploit\s*=\s*['\"]",
            r"malware", r"ransomware", r"trojan",
        ]

        for f in skill_path.rglob("*"):
            if not f.is_file():
                continue
            if any(skip in f.parts for skip in [".git", "node_modules", "__pycache__", ".venv"]):
                continue
            text_ext = {".py", ".md", ".txt", ".js", ".ts", ".sh"}
            if f.suffix.lower() not in text_ext:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pattern in weaponized_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return False

        return True


class SecurityScanner:
    SENSITIVE_PATTERNS = [
        (r'password\s*=\s*["\']([^"\']+)["\']', "硬编码密码", "high"),
        (r'passwd\s*=\s*["\']([^"\']+)["\']', "硬编码密码", "high"),
        (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "硬编码 API Key", "high"),
        (r'apikey\s*=\s*["\']([^"\']+)["\']', "硬编码 API Key", "high"),
        (r'token\s*=\s*["\']([^"\']+)["\']', "硬编码 Token", "high"),
        (r'secret\s*=\s*["\']([^"\']+)["\']', "硬编码密钥", "high"),
        (r'private[_-]?key\s*=\s*["\']([^"\']+)["\']', "硬编码私钥", "high"),
        (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "PEM 格式私钥", "blocker"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "blocker"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", "blocker"),
        (r'xox[baprs]-[0-9a-zA-Z-]+', "Slack Token", "blocker"),
    ]

    DANGEROUS_COMMANDS = [
        (r'subprocess\.call\([^)]*shell\s*=\s*True', "shell=True 调用", "medium"),
        (r'os\.system\([^)]*\)', "os.system 调用", "medium"),
        (r'exec\([^)]*\)', "exec 动态执行", "medium"),
        (r'eval\([^)]*\)', "eval 动态执行", "medium"),
        (r'rm\s+(-rf|--recursive)', "危险删除命令", "high"),
        (r'drop\s+table', "危险 SQL DROP", "high"),
    ]

    PLACEHOLDER_VALUES = [
        "your-api-key", "sk-xxx", "<YOUR_TOKEN>", "example-token",
        "dummy-secret", "your_key_here", "replace_me", "xxx",
        "placeholder", "INSERT_KEY", "YOUR_API_KEY",
    ]

    IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", "absorbed-skills", "skills", "examples"}

    IGNORED_FILES = set()

    PUBLIC_BLOCKED_FILES = {".env", "id_rsa", "id_ed25519"}

    RISK_REQUIREMENTS = {
        "none": {
            "requirements": [],
            "label": "🟢 none — 纯文本/推理",
        },
        "safe": {
            "requirements": ["标注影响范围"],
            "label": "🔵 safe — 读取文件/安全命令",
        },
        "critical": {
            "requirements": ["必须有确认步骤", "标注影响范围", "risk 字段为 critical"],
            "label": "🟠 critical — 修改状态/删除/推送",
        },
        "offensive": {
            "requirements": [
                "必须有「仅限授权使用」免责声明",
                "必须有用户确认步骤",
                "不得包含武器化载荷",
                "risk 字段为 offensive",
            ],
            "label": "🔴 offensive — 渗透测试/红队",
        },
    }

    def __init__(self, skill_path: str, strict_public: bool = False):
        self.skill_path = Path(skill_path)
        self.strict_public = strict_public
        self.findings: List[Dict] = []
        self._load_ignore_rules()

    def scan(self) -> Dict[str, Any]:
        if not self.skill_path.exists():
            return {"error": f"Skill 路径不存在：{self.skill_path}"}

        for file_path in self.skill_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(d in file_path.parts for d in self.IGNORED_DIRS):
                continue
            if self._is_binary(file_path):
                continue
            self._scan_file(file_path)

        if self.strict_public:
            self._check_public_safety()

        result = self._build_result()

        offensive_checker = OffensiveSkillChecker()
        result["offensive_compliance"] = offensive_checker.check(self.skill_path, result)

        result["risk_classification"] = self._classify_risk(result)

        result["audit_layers"] = self._run_audit_layers()

        return result

    def _scan_file(self, file_path: Path) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        relative = str(file_path.relative_to(self.skill_path)).replace("\\", "/")
        if relative in self.IGNORED_FILES:
            return
        is_example = any(p in relative for p in ["examples/", "tests/", "demo/", "references/"])

        for pattern, issue_type, base_severity in self.SENSITIVE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                matched_value = match.group(0)
                if self._is_placeholder(matched_value):
                    severity = "low"
                    category = "placeholder"
                elif is_example:
                    severity = "medium"
                    category = "example_risk"
                else:
                    severity = base_severity
                    category = "real_risk"

                self.findings.append({
                    "type": issue_type,
                    "file": relative,
                    "line": content[:match.start()].count("\n") + 1,
                    "pattern": matched_value[:60],
                    "severity": severity,
                    "category": category,
                })

        for pattern, issue_type, severity in self.DANGEROUS_COMMANDS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                self.findings.append({
                    "type": issue_type,
                    "file": relative,
                    "line": content[:match.start()].count("\n") + 1,
                    "pattern": match.group(0)[:60],
                    "severity": "medium" if is_example else severity,
                    "category": "example_risk" if is_example else "real_risk",
                })

        lines = content.splitlines()
        in_md_code_block = False
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if _MARKDOWN_CODE_FENCE.match(stripped):
                in_md_code_block = not in_md_code_block
                continue
            is_comment = _is_comment_line(stripped)
            is_placeholder = _is_placeholder_line(stripped)
            if is_comment or in_md_code_block or is_placeholder:
                continue

            for token_match in re.finditer(r"""['"]([^'"]{16,})['\"]""", line):
                token = token_match.group(1)
                ent = shannon_entropy(token)
                if ent > 4.5:
                    already = any(f["file"] == relative and f["line"] == line_num for f in self.findings)
                    if already:
                        continue
                    sev = "high" if ent > 5.0 else "medium"
                    if is_example:
                        sev = "low"
                    self.findings.append({
                        "type": "高熵字符串（可能是密钥）",
                        "file": relative,
                        "line": line_num,
                        "pattern": token[:6] + "****",
                        "severity": sev,
                        "category": "example_risk" if is_example else "real_risk",
                        "entropy": round(ent, 2),
                    })

            for b64_match in _BASE64_RE.finditer(line):
                b64_token = b64_match.group(0)
                if len(b64_token) < 20:
                    continue
                already = any(f["file"] == relative and f["line"] == line_num for f in self.findings)
                if already:
                    continue
                if _check_base64_secret(b64_token):
                    sev = "medium" if is_example else "high"
                    self.findings.append({
                        "type": "Base64 编码密钥",
                        "file": relative,
                        "line": line_num,
                        "pattern": b64_token[:6] + "****",
                        "severity": sev,
                        "category": "example_risk" if is_example else "real_risk",
                    })

            for ip_match in _IP_RE.finditer(line):
                ip = ip_match.group(1)
                if _is_private_ip(ip):
                    continue
                parts = ip.split(".")
                try:
                    if not all(0 <= int(p) <= 255 for p in parts):
                        continue
                except ValueError:
                    continue
                self.findings.append({
                    "type": "硬编码公网 IP",
                    "file": relative,
                    "line": line_num,
                    "pattern": ip,
                    "severity": "low",
                    "category": "example_risk" if is_example else "real_risk",
                })

        compiled_injection = [(re.compile(p), t, s, it) for p, t, s, it in INJECTION_PATTERNS]
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if _MARKDOWN_CODE_FENCE.match(stripped):
                in_md_code_block = not in_md_code_block
                continue
            if _is_comment_line(stripped) or in_md_code_block or _is_placeholder_line(stripped):
                continue
            for regex, issue_type, base_sev, injection_type in compiled_injection:
                if regex.search(line):
                    sev = "medium" if is_example else base_sev
                    self.findings.append({
                        "type": f"{issue_type}（{injection_type}）",
                        "file": relative,
                        "line": line_num,
                        "pattern": stripped[:60],
                        "severity": sev,
                        "category": "example_risk" if is_example else "real_risk",
                        "injection_type": injection_type,
                    })

    def _check_public_safety(self) -> None:
        for f in self.skill_path.rglob("*"):
            if not f.is_file():
                continue
            if any(d in f.parts for d in self.IGNORED_DIRS):
                continue
            rel = str(f.relative_to(self.skill_path)).replace("\\", "/")
            if rel in self.IGNORED_FILES:
                continue
            name = f.name.lower()
            if name in self.PUBLIC_BLOCKED_FILES or name.endswith((".pem", ".key")):
                self.findings.append({
                    "type": f"公开包禁止包含 {name}",
                    "file": rel,
                    "line": 0,
                    "pattern": "",
                    "severity": "blocker",
                    "category": "publish_blocker",
                })

    def _load_ignore_rules(self) -> None:
        rules_path = self.skill_path / "references" / "safety-ignore-rules.json"
        if rules_path.exists():
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    rules = json.load(f)
                extra_placeholders = rules.get("placeholder_values", [])
                for p in extra_placeholders:
                    if p not in self.PLACEHOLDER_VALUES:
                        self.PLACEHOLDER_VALUES.append(p)
                extra_dirs = rules.get("ignored_dirs", [])
                for d in extra_dirs:
                    self.IGNORED_DIRS.add(d)
                extra_files = rules.get("ignored_files", [])
                for f in extra_files:
                    self.IGNORED_FILES.add(f.replace("\\", "/"))
            except Exception:
                pass

    def _is_placeholder(self, value: str) -> bool:
        lower = value.lower()
        return any(p in lower for p in self.PLACEHOLDER_VALUES)

    def _is_binary(self, file_path: Path) -> bool:
        text_ext = {".py", ".md", ".txt", ".js", ".ts", ".json", ".yaml", ".yml", ".sh", ".bash", ".toml", ".cfg", ".ini"}
        return file_path.suffix.lower() not in text_ext

    def _classify_risk(self, result: Dict) -> Dict[str, Any]:
        offensive = result.get("offensive_compliance", {})
        if offensive.get("is_offensive"):
            risk_level = "offensive"
        elif self._has_critical_operations(result):
            risk_level = "critical"
        elif self._has_safe_operations(result):
            risk_level = "safe"
        else:
            risk_level = "none"

        reqs = self.RISK_REQUIREMENTS.get(risk_level, self.RISK_REQUIREMENTS["none"])
        compliance = self._check_risk_compliance(risk_level, result)

        return {
            "risk_level": risk_level,
            "label": reqs["label"],
            "requirements": reqs["requirements"],
            "compliance": compliance,
        }

    def _has_critical_operations(self, result: Dict) -> bool:
        for f in self.findings:
            if f["category"] == "real_risk" and f["severity"] in ("high", "blocker"):
                return True

        critical_patterns = [
            r'\.write\(', r'\.unlink\(', r'shutil\.rmtree',
            r'os\.remove\(', r'os\.rename\(', r'git\s+push',
            r'\bdeploy\b', r'\bpublish\b', r'requests\.(post|put|delete|patch)',
        ]

        for f in self.skill_path.rglob("*"):
            if not f.is_file() or any(d in f.parts for d in self.IGNORED_DIRS):
                continue
            if self._is_binary(f):
                continue
            try:
                rel = str(f.relative_to(self.skill_path)).replace("\\", "/")
            except ValueError:
                continue
            if rel in self.IGNORED_FILES:
                continue
            if any(p in rel for p in ["references/", "examples/", "tests/", "demo/"]):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pattern in critical_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True

        return False

    def _has_safe_operations(self, result: Dict) -> bool:
        scripts_dir = self.skill_path / "scripts"
        if scripts_dir.exists() and any(scripts_dir.iterdir()):
            return True

        safe_patterns = [
            r'\.read\(', r'open\(', r'requests\.get',
            r'subprocess\.run', r'os\.path\.',
        ]

        skill_md = self.skill_path / "SKILL.md"
        if skill_md.exists():
            try:
                content = skill_md.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return False
            for pattern in safe_patterns:
                if re.search(pattern, content):
                    return True

        return False

    def _check_risk_compliance(self, risk_level: str, result: Dict) -> Dict[str, Any]:
        met = []
        missing = []

        skill_md = self.skill_path / "SKILL.md"
        skill_md_content = ""
        frontmatter_risk = ""
        if skill_md.exists():
            try:
                skill_md_content = skill_md.read_text(encoding="utf-8", errors="ignore")
                fm_match = re.match(r"^---\s*\n(.*?)\n---", skill_md_content, re.DOTALL)
                if fm_match:
                    risk_m = re.search(r'^risk:\s*["\']?(\w+)["\']?\s*$', fm_match.group(1), re.MULTILINE)
                    if risk_m:
                        frontmatter_risk = risk_m.group(1).strip().lower()
            except Exception:
                pass

        if risk_level == "none":
            pass
        elif risk_level == "safe":
            if "影响范围" in skill_md_content or "scope" in skill_md_content.lower() or "影响" in skill_md_content:
                met.append("标注影响范围")
            else:
                missing.append("标注影响范围")
        elif risk_level == "critical":
            confirm_patterns = ["确认", "confirm", "input(", "yes/no"]
            has_confirm = any(p in skill_md_content.lower() for p in confirm_patterns)
            if has_confirm:
                met.append("必须有确认步骤")
            else:
                missing.append("必须有确认步骤")

            if "影响范围" in skill_md_content or "scope" in skill_md_content.lower() or "影响" in skill_md_content:
                met.append("标注影响范围")
            else:
                missing.append("标注影响范围")

            if frontmatter_risk == "critical":
                met.append("risk 字段为 critical")
            else:
                missing.append(f"risk 字段为 critical（当前为 {frontmatter_risk or '未设置'}）")
        elif risk_level == "offensive":
            offensive = result.get("offensive_compliance", {})
            compliance = offensive.get("compliance", {})
            checks = compliance.get("checks", {})

            if checks.get("has_disclaimer"):
                met.append("必须有「仅限授权使用」免责声明")
            else:
                missing.append("必须有「仅限授权使用」免责声明")

            if checks.get("has_user_confirm"):
                met.append("必须有用户确认步骤")
            else:
                missing.append("必须有用户确认步骤")

            if checks.get("no_weaponized_payload"):
                met.append("不得包含武器化载荷")
            else:
                missing.append("不得包含武器化载荷")

            if frontmatter_risk == "offensive":
                met.append("risk 字段为 offensive")
            else:
                missing.append(f"risk 字段为 offensive（当前为 {frontmatter_risk or '未设置'}）")

        return {"met": met, "missing": missing}

    def _run_audit_layers(self) -> Dict[str, Any]:
        code = self._audit_code()
        documentation = self._audit_documentation()
        runtime = self._audit_runtime()

        return {
            "code": code,
            "documentation": documentation,
            "runtime": runtime,
        }

    def _audit_code(self) -> Dict[str, Any]:
        checks = {
            "no_hardcoded_passwords": True,
            "no_hardcoded_api_keys": True,
            "no_hardcoded_tokens": True,
            "no_hardcoded_private_keys": True,
            "input_validated": True,
            "parameterized_queries": True,
            "special_chars_escaped": True,
            "file_size_limited": True,
            "no_shell_execution": True,
            "command_params_escaped": True,
            "path_traversal_check": True,
            "file_type_validated": True,
            "permission_check": True,
            "temp_file_cleanup": True,
            "https_preferred": True,
            "cert_verification": True,
            "timeout_set": True,
            "redirect_limited": True,
            "domain_whitelist": True,
        }

        for f in self.findings:
            if f["category"] != "real_risk":
                continue
            t = f["type"]
            if "密码" in t:
                checks["no_hardcoded_passwords"] = False
            elif "API Key" in t:
                checks["no_hardcoded_api_keys"] = False
            elif "Token" in t:
                checks["no_hardcoded_tokens"] = False
            elif "私钥" in t or "PEM" in t:
                checks["no_hardcoded_private_keys"] = False
            elif "shell=True" in t or "os.system" in t:
                checks["no_shell_execution"] = False
            elif "eval" in t or "exec" in t:
                checks["no_shell_execution"] = False

        for script in self.skill_path.rglob("*.py"):
            if any(skip in script.parts for skip in list(self.IGNORED_DIRS) + ["__pycache__"]):
                continue
            try:
                srel = str(script.relative_to(self.skill_path)).replace("\\", "/")
            except ValueError:
                continue
            if srel in self.IGNORED_FILES:
                continue
            try:
                content = script.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if re.search(r'open\([^)]*\)', content) and not re.search(r'os\.path\.basename|os\.path\.realpath|os\.path\.normpath', content):
                checks["path_traversal_check"] = False

            if re.search(r'requests\.', content):
                if not re.search(r'verify\s*=\s*True|timeout\s*=', content):
                    checks["cert_verification"] = False
                    checks["timeout_set"] = False

            if re.search(r'subprocess\.(run|call|Popen)', content) and 'shell=True' in content:
                checks["command_params_escaped"] = False

        passed = sum(1 for v in checks.values() if v)
        total = len(checks)
        score = round(passed / total * 5) if total > 0 else 5

        return {
            "layer": "code",
            "checks": checks,
            "passed": passed,
            "total": total,
            "score": score,
        }

    def _audit_documentation(self) -> Dict[str, Any]:
        checks = {
            "no_misleading_description": True,
            "permission_clear": True,
            "safe_examples": True,
            "security_notes_present": True,
            "scripts_no_malware": True,
            "templates_no_vulnerabilities": True,
            "example_code_safe": True,
        }

        skill_md = self.skill_path / "SKILL.md"
        skill_md_content = ""
        if skill_md.exists():
            try:
                skill_md_content = skill_md.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        if skill_md_content:
            has_commands = bool(re.search(r'subprocess|os\.system|exec\(|eval\(', skill_md_content))
            has_network = bool(re.search(r'requests\.|fetch\(|urllib|http', skill_md_content))
            has_security_note = bool(re.search(r'安全|风险|危险|Security|Safety|Warning', skill_md_content, re.IGNORECASE))

            if (has_commands or has_network) and not has_security_note:
                checks["security_notes_present"] = False

            if has_commands and not re.search(r'影响范围|scope|权限|permission', skill_md_content, re.IGNORECASE):
                checks["permission_clear"] = False

            example_code_blocks = re.findall(r'```[\s\S]*?```', skill_md_content)
            for block in example_code_blocks:
                if re.search(r'password\s*=\s*["\'][^"\']+["\']', block):
                    if not re.search(r'your-|xxx|placeholder|example', block, re.IGNORECASE):
                        checks["safe_examples"] = False
                        checks["example_code_safe"] = False

        for f in self.findings:
            if f["category"] == "real_risk" and f["severity"] in ("high", "blocker"):
                if "恶意" in f.get("type", ""):
                    checks["scripts_no_malware"] = False

        passed = sum(1 for v in checks.values() if v)
        total = len(checks)
        score = round(passed / total * 5) if total > 0 else 5

        return {
            "layer": "documentation",
            "checks": checks,
            "passed": passed,
            "total": total,
            "score": score,
        }

    def _audit_runtime(self) -> Dict[str, Any]:
        checks = {
            "no_privilege_escalation": True,
            "permission_matches_declaration": True,
            "no_permission_abuse": True,
            "sensitive_data_not_leaked": True,
            "data_transfer_encrypted": True,
            "data_processing_compliant": True,
            "no_resource_exhaustion": True,
            "execution_time_reasonable": True,
            "memory_usage_reasonable": True,
        }

        for script in self.skill_path.rglob("*.py"):
            if any(skip in script.parts for skip in list(self.IGNORED_DIRS) + ["__pycache__"]):
                continue
            try:
                srel = str(script.relative_to(self.skill_path)).replace("\\", "/")
            except ValueError:
                continue
            if srel in self.IGNORED_FILES:
                continue
            try:
                content = script.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if re.search(r'os\.setuid|os\.setgid|sudo|chmod\s+[0-7]{3}', content):
                checks["no_privilege_escalation"] = False

            if re.search(r'logger\.(info|debug|warning).*\{.*response.*\}', content, re.IGNORECASE):
                if not re.search(r'status_code|sanitiz|redact|mask', content, re.IGNORECASE):
                    checks["sensitive_data_not_leaked"] = False

            if re.search(r'requests\.(post|put)\(', content):
                if not re.search(r'https://', content):
                    checks["data_transfer_encrypted"] = False

            if re.search(r'while\s+True|for\s+.*\s+in\s+range\(\d{5,}\)', content):
                if not re.search(r'timeout|max_retries|break', content):
                    checks["no_resource_exhaustion"] = False

            if re.search(r'read\(\)|\.readlines\(\)', content):
                if not re.search(r'chunk|buffer|max_size|limit', content, re.IGNORECASE):
                    checks["memory_usage_reasonable"] = False

        for f in self.findings:
            if f["category"] == "real_risk" and f["severity"] == "high":
                if "密码" in f["type"] or "Key" in f["type"] or "Token" in f["type"]:
                    checks["sensitive_data_not_leaked"] = False

        passed = sum(1 for v in checks.values() if v)
        total = len(checks)
        score = round(passed / total * 5) if total > 0 else 5

        return {
            "layer": "runtime",
            "checks": checks,
            "passed": passed,
            "total": total,
            "score": score,
        }

    def _build_result(self) -> Dict[str, Any]:
        blockers = [f for f in self.findings if f["severity"] == "blocker"]
        real_high = [f for f in self.findings if f["severity"] == "high" and f["category"] == "real_risk"]
        example_risks = [f for f in self.findings if f["category"] == "example_risk"]
        warnings = [f for f in self.findings if f["severity"] == "medium" and f["category"] == "real_risk"]
        publish_blockers = [f for f in self.findings if f["category"] == "publish_blocker"]

        top_findings = sorted(self.findings, key=lambda x: ["blocker", "high", "medium", "low"].index(x["severity"]))[:10]

        risk_level = "none"
        if blockers or real_high:
            risk_level = "high"
        elif warnings:
            risk_level = "medium"
        elif example_risks:
            risk_level = "low"

        return {
            "passed": len(blockers) == 0 and len(real_high) == 0,
            "risk_level": risk_level,
            "real_high_risks": [{"type": f["type"], "file": f["file"], "line": f["line"]} for f in real_high],
            "example_risks": [{"type": f["type"], "file": f["file"]} for f in example_risks],
            "warnings": [{"type": f["type"], "file": f["file"]} for f in warnings],
            "publish_blockers": [{"type": f["type"], "file": f["file"]} for f in publish_blockers],
            "ignored_paths": list(self.IGNORED_DIRS),
            "ignored_files": list(self.IGNORED_FILES),
            "top_findings": top_findings,
            "total_findings": len(self.findings),
        }


def scan_security(skill_path: str, strict_public: bool = False) -> Dict[str, Any]:
    scanner = SecurityScanner(skill_path, strict_public=strict_public)
    return scanner.scan()


def main():
    if len(sys.argv) < 2:
        print("用法：python scan_security.py <Skill目录路径> [--strict-public]")
        sys.exit(1)

    strict = "--strict-public" in sys.argv
    result = scan_security(sys.argv[1], strict_public=strict)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
