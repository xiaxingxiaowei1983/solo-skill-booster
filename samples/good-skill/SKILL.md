---
name: api-doc-generator
description: "从代码自动生成API文档的Skill，支持OpenAPI 3.0格式，自动提取路由、参数、响应结构，适合后端开发者快速产出标准API文档"
description_zh: "API文档自动生成器"
description_en: "API Document Generator"
version: 1.2.0
---

# API文档自动生成器

从代码自动生成API文档，支持OpenAPI 3.0格式。帮后端开发者省掉手动写API文档的重复劳动，3分钟从代码到可发布的标准文档。适合需要频繁维护API文档的后端团队使用。

## 使用场景

### 适合使用此技能的情况:
- 后端开发者写完API后需要补文档
- 团队需要统一API文档格式
- 代码更新后文档需要同步更新
- 需要生成OpenAPI 3.0兼容的文档用于Swagger展示

### 为什么做它

团队5个后端，每周至少2小时写/改API文档，格式不统一，经常漏参数。用这个Skill，3分钟从代码生成标准文档，省掉每周至少2小时的文档维护时间。

### 做出来之后省掉了什么

- 不用手动写路由、参数、响应格式
- 代码改了文档自动同步
- 团队文档格式统一，不再各写各的

### 不适合的情况:
- 前端组件文档（用JSDoc更适合）
- 非HTTP API（如gRPC、GraphQL需另行处理）
- 已有完善的API文档系统

## 使用步骤

1. 指向你的API代码目录
2. Skill自动扫描路由定义、参数校验、响应结构
3. 生成OpenAPI 3.0格式文档
4. 可选：输出Markdown版本用于Wiki

### 触发方式

- "帮我生成API文档" — 完整模式
- "快速生成API文档" — 快速模式（只生成路由和参数）
- "更新API文档" — 增量更新模式

## 示例

### 示例1：Express项目生成文档

输入（Express路由代码）：
```javascript
// routes/users.js
router.get('/api/users', validate(querySchema), userController.list);
router.post('/api/users', validate(bodySchema), userController.create);
router.get('/api/users/:id', userController.getById);
router.delete('/api/users/:id', auth.requireAdmin, userController.remove);
```

输出（openapi.yaml）：
```yaml
openapi: 3.0.0
info:
  title: My Project API
  version: 1.0.0
paths:
  /api/users:
    get:
      summary: 获取用户列表
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            default: 1
        - name: pageSize
          in: query
          schema:
            type: integer
            default: 20
      responses:
        '200':
          description: 成功返回用户列表
          content:
            application/json:
              schema:
                type: object
                properties:
                  users:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'
                  total:
                    type: integer
    post:
      summary: 创建用户
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserRequest'
      responses:
        '201':
          description: 用户创建成功
  /api/users/{id}:
    get:
      summary: 获取用户详情
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: 成功返回用户详情
    delete:
      summary: 删除用户（需管理员权限）
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '204':
          description: 删除成功
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
        email:
          type: string
```

### 示例2：增量更新

输入：指向已更新的路由文件
输出：只更新变更的部分，保留手动补充的描述（智能合并）

## 创作过程

### 为什么做它

团队5个后端，每周至少2小时写/改API文档，格式不统一，经常漏参数。

### 踩过的坑

1. **路由解析不一致**：Express和Koa的路由定义方式不同，需要适配两种格式
2. **参数推断不准**：Joi校验和TypeScript类型需要双重扫描
3. **手动描述丢失**：增量更新时不能覆盖用户手动补充的描述

### 解决方案

1. 双解析器：支持Express和Koa两种路由格式
2. 类型推断+校验扫描：同时读取TypeScript类型和Joi校验
3. 智能合并：只更新自动生成的部分，保留手动描述

## 与同类Skill的区别

| 维度 | 本Skill | 通用文档生成器 |
|------|---------|---------------|
| 格式 | OpenAPI 3.0标准 | 自定义格式 |
| 增量更新 | 支持，保留手动描述 | 不支持，全量覆盖 |
| 多框架 | Express + Koa | 通常只支持一种 |
| 输出 | YAML + Markdown双格式 | 单一格式 |
| AI推断 | 无注释代码自动推断参数描述 | 需要手动写注释 |

## 不做什么

- 不生成前端代码（只生成文档）
- 不替代API设计（只从已有代码生成）
- 不处理非HTTP API
- 不自动发布到Swagger（需手动上传）

## 已知限制

- gRPC和GraphQL暂不支持
- 复杂嵌套类型可能需要手动补充
- 需要代码中有基本的类型定义或校验

## 依赖

- Node.js 18+
- 项目需有TypeScript类型定义或Joi校验
- Python 3.8+（用于解析脚本）

## 文件结构

```
api-doc-generator/
├── SKILL.md                    # 本文件
├── README.md                   # 项目说明
├── QUICKSTART.md               # 快速上手
├── references/
│   ├── express-parser.md       # Express路由解析规则
│   └── openapi-spec.md         # OpenAPI 3.0规范参考
├── scripts/
│   ├── generate.py             # 主生成脚本
│   ├── merge.py                # 智能合并脚本
│   └── requirements.txt        # Python依赖
└── templates/
    └── openapi-base.yaml       # OpenAPI基础模板
```

## Changelog

### v1.2.0
- 新增：AI推断层，无注释代码自动推断参数描述
- 新增：Koa路由解析支持
- 修复：增量更新时手动描述丢失问题

### v1.0.0
- 初始版本：Express路由解析 + OpenAPI 3.0生成
- 支持：YAML + Markdown双格式输出
