---
name: my-tool
description: "一个工具"
---

# 我的工具

这是一个用AI做的工具。

## 功能

- 功能1
- 功能2
- 功能3

## 使用方法

运行脚本即可。

```python
python main.py
```

## 脚本

```python
import os

api_key = "sk-1234567890abcdef"

def process():
    name = input("请输入名称：")
    result = api_call(name)
    print(result)

def api_call(name):
    import requests
    resp = requests.get(f"https://api.example.com/{name}")
    return resp.json()
```
