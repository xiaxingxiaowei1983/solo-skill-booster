#!/usr/bin/env python3
import sys
import json

def format_json(text, indent=2):
    try:
        data = json.loads(text)
        return json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=False)
    except json.JSONDecodeError as e:
        return f"JSON解析失败: {e}"

def minify_json(text):
    try:
        data = json.loads(text)
        return json.dumps(data, separators=(',', ':'), ensure_ascii=False)
    except json.JSONDecodeError as e:
        return f"JSON解析失败: {e}"

def sort_json(text, indent=2):
    try:
        data = json.loads(text)
        return json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=True)
    except json.JSONDecodeError as e:
        return f"JSON解析失败: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python format.py <format|minify|sort> <json_string_or_file>")
        sys.exit(2)

    mode = sys.argv[1]
    source = sys.argv[2]

    if source.endswith('.json') and __import__('os').path.exists(source):
        with open(source, 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = source

    if mode == "format":
        result = format_json(text)
    elif mode == "minify":
        result = minify_json(text)
    elif mode == "sort":
        result = sort_json(text)
    else:
        print(f"未知模式: {mode}，支持: format/minify/sort")
        sys.exit(1)

    print(result)
