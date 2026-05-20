#!/usr/bin/env python3
import sys
import json

def diff_json(text1, text2):
    try:
        data1 = json.loads(text1)
        data2 = json.loads(text2)
    except json.JSONDecodeError as e:
        return f"JSON解析失败: {e}"

    changes = []
    _compare(data1, data2, "", changes)

    if not changes:
        return "✅ 两个JSON完全相同"

    lines = ["❌ 发现差异：\n"]
    for change in changes:
        lines.append(f"  {change['type']}: {change['path']}")
        if change['type'] == '修改':
            lines.append(f"    旧值: {change['old']}")
            lines.append(f"    新值: {change['new']}")
        elif change['type'] == '新增':
            lines.append(f"    值: {change['value']}")
    return "\n".join(lines)

def _compare(obj1, obj2, path, changes):
    if type(obj1) != type(obj2):
        changes.append({"type": "修改", "path": path, "old": type(obj1).__name__, "new": type(obj2).__name__})
        return
    if isinstance(obj1, dict):
        for key in obj1:
            new_path = f"{path}.{key}" if path else key
            if key not in obj2:
                changes.append({"type": "删除", "path": new_path})
            else:
                _compare(obj1[key], obj2[key], new_path, changes)
        for key in obj2:
            if key not in obj1:
                new_path = f"{path}.{key}" if path else key
                changes.append({"type": "新增", "path": new_path, "value": obj2[key]})
    elif isinstance(obj1, list):
        for i in range(max(len(obj1), len(obj2))):
            new_path = f"{path}[{i}]"
            if i >= len(obj1):
                changes.append({"type": "新增", "path": new_path, "value": obj2[i]})
            elif i >= len(obj2):
                changes.append({"type": "删除", "path": new_path})
            else:
                _compare(obj1[i], obj2[i], new_path, changes)
    else:
        if obj1 != obj2:
            changes.append({"type": "修改", "path": path, "old": obj1, "new": obj2})

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python diff.py <json1_string_or_file> <json2_string_or_file>")
        sys.exit(2)

    def load_source(source):
        if source.endswith('.json') and __import__('os').path.exists(source):
            with open(source, 'r', encoding='utf-8') as f:
                return f.read()
        return source

    text1 = load_source(sys.argv[1])
    text2 = load_source(sys.argv[2])
    result = diff_json(text1, text2)
    print(result)
