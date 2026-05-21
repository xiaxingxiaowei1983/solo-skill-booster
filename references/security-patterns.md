# 安全模式参考 — 专业安全扫描检测规则

> 从 SOLO Skill 评审官吸收的专业安全扫描能力，作为提分官安全检查的参考依据

## Shannon 熵检测

高熵字符串（熵值 > 4.5）可能是硬编码密钥或 Token。

| 熵值范围 | 风险等级 | 说明 |
|----------|---------|------|
| > 5.0 | high | 极大概率是密钥/Token |
| 4.5 - 5.0 | medium | 可能是密钥，需人工确认 |
| < 4.5 | low | 大概率是普通字符串 |

## 15 种注入模式

| 模式 | 类型 | 风险 | 检测正则 |
|------|------|------|---------|
| eval 动态执行 | code_injection | high | `\beval\s*\(` |
| exec 动态执行 | code_injection | high | `\bexec\s*\(` |
| shell=True 调用 | command_injection | high | `subprocess\.(?:call\|run\|Popen\|check_output\|check_call)\s*\([^)]*shell\s*=\s*True` |
| os.system 调用 | command_injection | high | `\bos\.system\s*\(` |
| f-string SQL 查询 | sql_injection | high | `\bf['\"](?:[^'\"]*?)(?:SELECT\|INSERT\|UPDATE\|DELETE\|DROP\|ALTER)\b` |
| 用户输入拼入 LLM prompt | prompt_injection | high | `(?:prompt\|system_prompt\|user_prompt\|messages?)\s*=\s*f['\"][^'\"]*\{(?:user\|input\|query\|request\|data)` |
| innerHTML 赋值 | xss | medium | `\.innerHTML\s*=\s*(?!['\"]\s*$)[^;]+` |
| 用户可控 URL HTTP 请求 | ssrf | medium | `\brequests\.(?:get\|post\|put\|patch\|delete)\s*\([^)]*(?:\bvar\b\|\bdata\b\|\brequest\b\|\bparams?\b\|\burl\b)` |
| 用户可控路径文件操作 | path_traversal | high | `\bopen\s*\([^)]*(?:\brequest\b\|\bparams?\b\|\bquery\b\|\bform\b\|\buser\b\|\bargv\b)` |

## 敏感信息模式

| 模式 | 风险 | 说明 |
|------|------|------|
| `password = "xxx"` | high | 硬编码密码 |
| `api_key = "xxx"` | high | 硬编码 API Key |
| `token = "xxx"` | high | 硬编码 Token |
| `secret = "xxx"` | high | 硬编码密钥 |
| `private_key = "xxx"` | high | 硬编码私钥 |
| `-----BEGIN PRIVATE KEY-----` | blocker | PEM 格式私钥 |
| `AKIA[0-9A-Z]{16}` | blocker | AWS Access Key |
| `ghp_[a-zA-Z0-9]{36}` | blocker | GitHub PAT |
| `xox[baprs]-[0-9a-zA-Z-]+` | blocker | Slack Token |

## 占位符白名单

以下值不会触发安全告警（属于示例/占位符）：

```
your-api-key, sk-xxx, <YOUR_TOKEN>, example-token,
dummy-secret, your_key_here, replace_me, xxx,
placeholder, INSERT_KEY, YOUR_API_KEY, changeme,
todo, fixme, dummy, fake, sample, test123,
sk_test_, pk_test_
```

## 三层审计

| 层级 | 检查内容 | 项数 |
|------|---------|------|
| Code 层 | 硬编码检测、输入验证、参数化查询、路径遍历、证书验证等 | 19项 |
| Documentation 层 | 误导性描述、权限说明、安全备注、示例安全性等 | 7项 |
| Runtime 层 | 提权、权限滥用、数据泄露、加密传输、资源耗尽等 | 9项 |

## 风险分级与合规要求

| 风险等级 | 标签 | 合规要求 |
|---------|------|---------|
| none | 🟢 纯文本/推理 | 无 |
| safe | 🔵 读取文件/安全命令 | 标注影响范围 |
| critical | 🟠 修改状态/删除/推送 | 确认步骤 + 影响范围 + risk=critical |
| offensive | 🔴 渗透测试/红队 | 免责声明 + 确认步骤 + 无武器化载荷 + risk=offensive |

## 使用方式

```bash
python scripts/scan_security.py ./your-skill
python scripts/scan_security.py ./your-skill --strict-public
```
