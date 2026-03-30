# 架构设计

Pasion 是面向 Palpo 的身份、通知、运营与接入平台。它以 PostgreSQL 为唯一外部存储依赖，支持水平扩展部署。

## 设计目标

- 面向 Palpo 的身份、通知、运营与接入平台
- 支持 Matrix OIDC 认证（[MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861)）同时提供独立的用户运营能力
- 工作流驱动的业务流程管理
- 统一通知中心
- 可插拔的外部系统连接器

## Crate 结构

整个项目是一个 [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)，包含约 28 个 crate，按职责划分为以下几层。

### 核心平台层

| Crate | 说明 |
|-------|------|
| `pasion` | CLI 主入口 |
| `pasion-config` | 配置管理 |
| `pasion-data-model` | 领域数据模型 |
| `pasion-storage` | 存储抽象层 |
| `pasion-storage-pg` | PostgreSQL 实现 |
| `pasion-handlers` | HTTP 适配层（REST/OAuth2/Admin） |
| `pasion-router` | URL 路由定义 |
| `pasion-policy` | 策略引擎（OPA + Cedar） |
| `pasion-tasks` | 后台任务与工作流调度 |

### 通知与消息

| Crate | 说明 |
|-------|------|
| `pasion-messaging` | 统一通知中心（NotificationCenter） |
| `pasion-email` | 邮件发送（SMTP/Sendmail） |
| `pasion-sms` | 短信发送（Twilio/阿里云/腾讯云） |
| `pasion-templates` | 模板渲染 |

### 外部接入

| Crate | 说明 |
|-------|------|
| `pasion-matrix` | Matrix 连接器抽象 |
| `pasion-matrix-palpo` | Palpo 连接器实现 |
| `pasion-oidc-client` | 上游 OIDC/OAuth2 客户端 |

### 协议与加密

| Crate | 说明 |
|-------|------|
| `oauth2-types` | OAuth 2.0 / OIDC 类型 |
| `pasion-jose` | JWT/JWS/JWK |
| `pasion-keystore` | 密钥管理 |

### 前端与框架

| Crate | 说明 |
|-------|------|
| `pasion-frontend` | Dioxus 前端（Rust SPA） |
| `pasion-salvo-utils` | Salvo 框架工具 |
| `pasion-i18n` | 国际化 |

### 基础设施

| Crate | 说明 |
|-------|------|
| `pasion-http` | HTTP 工具 |
| `pasion-listener` | 网络监听 |
| `pasion-context` | 上下文工具 |
| `iana` / `iana-codegen` | IANA 注册表 |

## 关键依赖

### 异步运行时：`tokio`

[Tokio](https://tokio.rs/) 是项目使用的异步运行时。

### Web 框架：`salvo`

HTTP 层使用 [Salvo](https://salvo.rs/) 框架处理请求路由和中间件。

### 数据库：`diesel`

通过 [`diesel`](https://diesel.rs/) 和 [`diesel-async`](https://docs.rs/diesel-async/) 与数据库交互，使用 [`deadpool`](https://docs.rs/deadpool/) 管理连接池。数据库迁移由 `diesel_migrations` 处理。

### 模板引擎：`minijinja`

[MiniJinja](https://github.com/mitsuhiko/minijinja) 用于渲染登录、注册等页面模板。它是 Jinja2 模板语言的 Rust 实现，语法与 Python 的 Jinja2 基本一致。

### 可观测性：`tracing` + OpenTelemetry

日志通过 [`tracing`](https://docs.rs/tracing/*/tracing/) crate 处理，支持结构化日志和 OpenTelemetry 分布式追踪。

### 错误处理：`thiserror` / `anyhow`

- [`thiserror`](https://docs.rs/thiserror/) — 定义自定义错误类型
- [`anyhow`](https://docs.rs/anyhow/) — 错误链传播

### 密码学：RustCrypto

使用 [RustCrypto](https://github.com/RustCrypto) 系列 crate 处理加密操作。

## 请求处理流程

```
HTTP 请求
    │
    ▼
Salvo 路由器 + 中间件（日志、追踪、状态注入）
    │
    ▼
Handler（HTTP 适配层）
    │  - 请求解析
    │  - 参数校验
    │  - 响应映射
    │
    ▼
Workflow / Service 层
    │  - account_registration（注册工作流）
    │  - account_recovery（恢复工作流）
    │  - account_contacts（联系方式验证）
    │  - account_password（密码管理）
    │  - account_sessions（会话管理）
    │  - account_profile（用户资料）
    │  - account_access（登录/登出）
    │  - oauth2_access（OAuth2 授权/同意）
    │  - upstream_link_workflow（上游链接）
    │
    ├────────────────┬────────────────┐
    ▼                ▼                ▼
Repository      Connector       Notification
(storage-pg)    (matrix-palpo)  (messaging)
    │                │                │
    ▼                ▼                ▼
PostgreSQL       Palpo API      Email / SMS
```

Handler 层负责 HTTP 协议的适配——解析请求、校验参数、映射响应格式。业务逻辑集中在 Workflow / Service 层，每个工作流封装一个完整的业务流程（如注册、恢复、登录等）。工作流通过三类基础设施完成实际操作：

- **Repository**（`pasion-storage-pg`）：持久化读写，对接 PostgreSQL。
- **Connector**（`pasion-matrix-palpo`）：与外部系统（如 Palpo）的双向通信。
- **Notification**（`pasion-messaging`）：统一通知中心，将邮件和短信通过对应通道发送。
