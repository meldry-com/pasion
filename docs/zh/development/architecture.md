# 架构设计

Pasion 设计为轻量级、易于嵌入的服务，仅依赖 PostgreSQL 数据库。它可以轻松水平扩展。

## 设计目标

- 支持 Matrix 向 OpenID Connect 认证架构的迁移（[MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861)）
- 专注于 Matrix 特定需求，不追求成为通用身份提供商
- 仅使用 OIDC 协议进行认证；如需 SAML、CAS 或 LDAP，需搭配其他服务（如 [Dex](https://dexidp.io) 或 [Keycloak](https://www.keycloak.org)）

## Crate 结构

整个项目是一个 [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)，包含多个 crate：

| Crate | 说明 |
|-------|------|
| `pasion` | 命令行工具，主入口 |
| `pasion-config` | 配置文件解析和加载 |
| `pasion-data-model` | 数据库对象模型 |
| `pasion-email` | 邮件发送抽象层 |
| `pasion-handlers` | HTTP 请求处理逻辑 |
| `pasion-jose` | JWT/JWS/JWE/JWK 加密操作 |
| `pasion-storage` | 存储后端抽象 |
| `pasion-storage-pg` | PostgreSQL 存储实现 |
| `pasion-tasks` | 异步任务队列 |
| `pasion-router` | URL 路由定义 |
| `pasion-templates` | 页面模板渲染 |
| `oauth2-types` | OAuth 2.0 / OIDC 类型定义 |

## 关键依赖

### 异步运行时：`tokio`

[Tokio](https://tokio.rs/) 是项目使用的异步运行时。

### 日志和追踪：`tracing`

日志通过 [`tracing`](https://docs.rs/tracing/*/tracing/) crate 处理，支持结构化日志和 OpenTelemetry 分布式追踪。

### 错误处理：`thiserror` / `anyhow`

- [`thiserror`](https://docs.rs/thiserror/) — 定义自定义错误类型
- [`anyhow`](https://docs.rs/anyhow/) — 错误链传播

### 数据库：`sqlx`

通过 [`sqlx`](https://github.com/launchbadge/sqlx) 与数据库交互，支持编译时 SQL 查询检查。

### Web 框架：`salvo`

HTTP 层使用 [Salvo](https://salvo.rs/) 框架处理请求路由和中间件。

### 模板引擎：`tera`

[Tera](https://tera.netlify.app/) 用于渲染登录、注册等页面模板。

### 密码学：RustCrypto

使用 [RustCrypto](https://github.com/RustCrypto) 系列 crate 处理加密操作。

## 请求处理流程

```
HTTP 请求
    │
    ▼
反向代理（nginx）
    │
    ▼
Salvo 路由器
    │
    ├── 中间件：日志、追踪、状态注入
    │
    ▼
Handler 函数
    │
    ├── 从 Depot 获取依赖（数据库、配置等）
    ├── 执行业务逻辑
    ├── 与数据库交互
    │
    ▼
HTTP 响应
```
