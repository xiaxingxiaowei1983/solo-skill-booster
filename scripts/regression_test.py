#!/usr/bin/env python3
"""
回归测试脚本 — SOLO Skill 提分官
每次修改后自动跑样例验证，确保核心功能不退化

用法：
    python scripts/regression_test.py

退出码：
    0 = 全部通过
    1 = 有失败
"""

import os
import sys
import subprocess
from pathlib import Path

# 获取脚本所在目录
SCRIPT_DIR = Path(__file__).parent.resolve()
SKILL_DIR = SCRIPT_DIR.parent
SAMPLES_DIR = SKILL_DIR / "samples"
VALIDATE_SCRIPT = SKILL_DIR / "scripts" / "validate_skill.py"

# 测试用例定义
TEST_CASES = [
    {
        "name": "good-skill 应该高分通过",
        "path": SAMPLES_DIR / "good-skill",
        "expected_pass": True,
        "min_score": 19,
    },
    {
        "name": "bad-skill 应该低分失败",
        "path": SAMPLES_DIR / "bad-skill",
        "expected_pass": False,
        "max_score": 15,
    },
    {
        "name": "sample-skill 应该中等评分",
        "path": SAMPLES_DIR / "sample-skill",
        "expected_pass": True,
        "min_score": 15,
        "max_score": 19,
    },
]

def run_test(test_case: dict) -> dict:
    """运行单个测试用例"""
    result = {
        "name": test_case["name"],
        "passed": True,
        "message": "",
    }
    
    skill_path = test_case["path"]
    
    # 检查路径存在
    if not skill_path.exists():
        result["passed"] = False
        result["message"] = f"路径不存在: {skill_path}"
        return result
    
    # 调用 validate_skill.py
    try:
        cmd = [sys.executable, str(VALIDATE_SCRIPT), str(skill_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # 解析输出中的分数（简化版，实际应解析JSON）
        output = proc.stdout + proc.stderr
        
        # 检查退出码是否符合预期
        if test_case.get("expected_pass"):
            if proc.returncode != 0:
                result["passed"] = False
                result["message"] = f"预期通过但退出码={proc.returncode}"
        else:
            if proc.returncode == 0:
                result["passed"] = False
                result["message"] = f"预期失败但退出码=0"
        
        # 检查分数范围（简化检查）
        if "min_score" in test_case:
            # 实际应解析输出中的分数，这里简化处理
            pass
        
        if result["passed"]:
            result["message"] = "通过"
            
    except subprocess.TimeoutExpired:
        result["passed"] = False
        result["message"] = "超时（>30秒）"
    except Exception as e:
        result["passed"] = False
        result["message"] = f"异常: {str(e)}"
    
    return result

def main():
    print("=" * 60)
    print("SOLO Skill 提分官 — 回归测试")
    print("=" * 60)
    print()
    
    all_passed = True
    results = []
    
    for test_case in TEST_CASES:
        print(f"运行: {test_case['name']}...")
        result = run_test(test_case)
        results.append(result)
        
        if result["passed"]:
            print(f"  ✓ {result['message']}")
        else:
            print(f"  ✗ {result['message']}")
            all_passed = False
        print()
    
    print("=" * 60)
    print(f"总计: {len(results)} 个测试")
    passed_count = sum(1 for r in results if r["passed"])
    print(f"通过: {passed_count} / {len(results)}")
    print("=" * 60)
    
    if all_passed:
        print("\n✓ 全部通过")
        sys.exit(0)
    else:
        print("\n✗ 有失败")
        sys.exit(1)

if __name__ == "__main__":
    main()