#!/usr/bin/env python3
"""Good Skill 报告格式化脚本 — 演示输出格式化能力"""

import sys
import json
from datetime import datetime


def format_report(data, output_format="markdown"):
    if output_format == "markdown":
        return _format_markdown(data)
    elif output_format == "json":
        return json.dumps(data, ensure_ascii=False, indent=2)
    else:
        raise ValueError(f"Unsupported format: {output_format}")


def _format_markdown(data):
    lines = [
        f"# {data.get('name', 'Unknown')} Report",
        f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Summary",
        f"- **Score**: {data.get('score', 'N/A')}",
        f"- **Level**: {data.get('level', 'N/A')}",
        f"- **Verdict**: {data.get('verdict', 'N/A')}",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sample = {"name": "good-skill", "score": 22, "level": "S", "verdict": "PASS"}
    print(format_report(sample))
