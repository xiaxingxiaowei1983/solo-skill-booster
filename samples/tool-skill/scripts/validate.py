#!/usr/bin/env python3
import sys
import json

def validate_json(text):
    try:
        json.loads(text)
        return "✅ JSON校验通过"
    except json.JSONDecodeError as e:
        return f"❌ JSON校验失败\n位置：第{e.lineno}行，第{e.colno}字符\n原因：{e.msg}\n修复建议：检查该位置附近的语法"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python validate.py <json_string_or_file>")
        sys.exit(2)

    source = sys.argv[1]

    if source.endswith('.json') and __import__('os').path.exists(source):
        with open(source, 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = source

    result = validate_json(text)
    print(result)
    sys.exit(0 if "通过" in result else 1)
