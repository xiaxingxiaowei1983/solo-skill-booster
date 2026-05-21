---
name: json-formatter
description: "JSON格式化与校验工具，支持压缩/美化/排序/差异对比，适合开发者快速处理JSON数据"
description_zh: "JSON格式化校验器"
description_en: "JSON Formatter & Validator"
version: 1.0.0
---

# JSON格式化校验器

帮开发者一键处理JSON数据：格式化、校验、压缩、排序、差异对比。省掉每次打开在线工具的步骤，直接在SOLO中完成。适合需要频繁处理JSON的后端开发者和API调试人员使用。

## 使用场景

### 适合使用此技能的情况:
- 后端开发者调试API返回的JSON数据
- 需要对比两个JSON的差异
- 需要校验JSON格式是否正确
- 需要压缩JSON用于传输

### 为什么做它

每次调试API都要打开浏览器找在线JSON工具，还要担心数据泄露。用这个Skill，直接在本地处理，3秒出结果。

### 做出来之后省掉了什么

- 不用打开浏览器找在线工具
- 数据不离开本地，更安全
- 一条命令完成格式化/校验/压缩

### 不适合的情况:
- 需要JSON Schema校验（用ajv更专业）
- 需要JSON Path查询（用jq更强大）
- 超大JSON文件（>10MB建议用流式处理）

## 使用步骤

1. 提供JSON文本或文件路径
2. 选择操作：format（美化）/ minify（压缩）/ validate（校验）/ sort（排序）/ diff（差异对比）
3. 输出处理结果

### 触发方式

- "格式化JSON" / "美化JSON" — format模式
- "压缩JSON" — minify模式
- "校验JSON" — validate模式
- "排序JSON" — sort模式
- "对比JSON" — diff模式

## 示例

### 示例1：格式化JSON

输入：
```
{"name":"test","version":"1.0","dependencies":{"express":"^4.18"}}
```

输出：
```json
{
  "name": "test",
  "version": "1.0",
  "dependencies": {
    "express": "^4.18"
  }
}
```

### 示例2：校验JSON

输入：
```
{"name": "test", "version": }
```

输出：
```
❌ JSON校验失败
位置：第1行，第28字符
原因：期望值（字符串/数字/布尔/null/对象/数组），但遇到 '}'
修复建议：检查该位置附近的语法
```

## 输出格式

- format：缩进2空格的美化JSON
- minify：单行压缩JSON
- validate：✅ 通过 或 ❌ 失败+位置+原因+修复建议
- sort：按键名字典序排列的JSON
- diff：差异对比表（新增/删除/修改）

## 不做什么

- 不做JSON Schema校验
- 不做JSON Path查询
- 不处理YAML/TOML等其他格式
- 不发送数据到外部服务

## 已知限制

- 单次处理JSON大小建议<10MB
- diff模式仅支持两个JSON对比
- 排序仅支持键名字典序

## 依赖

- Python 3.8+
- 无第三方依赖（使用标准库json/jsonlib）

## 文件结构

```
json-formatter/
├── SKILL.md
├── scripts/
│   ├── format.py          # 格式化/压缩/排序
│   ├── validate.py        # 校验
│   └── diff.py            # 差异对比
└── README.md
```
