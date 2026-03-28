# Pasion

面向 [Palpo](https://palpo.im/) Matrix 聊天服务器的 OAuth 2.0 / OpenID Connect 身份认证与用户管理服务。

## 概述

Pasion 基于 OpenID Connect 协议为 Matrix 聊天服务器提供身份认证服务，以现代化、标准化的方式替代 Matrix 传统的登录系统，实现 [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861) 规范。

### 核心特性

- **OAuth 2.0 与 OpenID Connect** — 完整的 OIDC 提供者，支持授权码、客户端凭证、设备码等授权流程
- **上游 SSO 联合登录** — 对接外部身份提供商（Google、GitHub、GitLab、Apple、Keycloak、LDAP via Dex、QQ、微信、企业微信、飞书、Lark、钉钉等）
- **管理 API** — RESTful JSON 接口，管理用户、会话和 OAuth 2.0 客户端
- **策略引擎** — 基于 OPA (WebAssembly) 的可扩展策略引擎，实现细粒度访问控制
- **安全机制** — Argon2id 密码哈希、加密 Cookie、限流、CAPTCHA 支持
- **国际化** — 多语言 UI，支持可配置模板
- **可观测性** — OpenTelemetry 链路追踪和 Prometheus 指标导出

## 快速开始

### 1. 安装

**预编译二进制 (Linux)**

```bash
curl -sL https://github.com/taidge/pasion/releases/latest/download/pasion-x86_64-linux.tar.gz | tar xz
mv pasion /usr/local/bin/
```

**Docker**

```bash
docker pull ghcr.io/taidge/pasion:latest
```

**从源码编译**

```bash
git clone https://github.com/taidge/pasion.git
cd pasion
cd front && npm ci && npm run build && cd ..
cargo build --release
```

### 2. 准备数据库

```sql
CREATE USER pasion WITH PASSWORD 'your_password';
CREATE DATABASE pasion WITH OWNER pasion;
```

### 3. 生成并编辑配置

```bash
pasion config generate > config.yaml
# 编辑 config.yaml，参见下方配置说明
```

### 4. 启动服务

```bash
pasion server -c config.yaml
```

一条命令完成数据库迁移、启动 HTTP 服务和后台任务 worker。

## 配置说明

Pasion 使用 YAML 配置文件，核心配置项：

```yaml
# 公网访问地址
http:
  public_base: https://auth.example.com/
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      resources:
        - name: discovery     # OIDC 发现端点
        - name: human         # 登录 / 注册 UI
        - name: oauth         # OAuth 2.0 端点
        - name: health        # 健康检查
        - name: assets        # 前端静态资源

# 数据库连接
database:
  uri: postgresql://pasion:password@localhost/pasion

# Matrix 服务器集成
matrix:
  homeserver: matrix.example.com
  secret: "与 homeserver 共享的密钥"
  endpoint: "https://matrix.example.com"

# 加密与签名密钥
secrets:
  encryption: "base64编码的32字节密钥"
  keys:
    - kid: "key-id-1"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----

# 密码认证
passwords:
  enabled: true
  schemes:
    - version: 1
      algorithm: argon2id

# 上游 SSO 提供商（可选）
upstream_oauth2:
  providers:
    - id: "01HFRQFT5QFBM3Y5BHNFHMP6M0"
      issuer: "https://accounts.google.com/"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      token_endpoint_auth_method: client_secret_post
      scope: "openid email profile"

# 邮件（可选，用于验证和找回密码）
email:
  from: '"Pasion" <noreply@example.com>'
  transport: smtp
  mode: starttls
  hostname: smtp.example.com
```

完整配置参考请查阅[配置文档](docs/zh/reference/configuration.md)。

## 部署架构

Pasion 部署在 Matrix homeserver 旁边，由反向代理统一接入。Pasion 处理所有认证流程，homeserver 处理 Matrix 协议（消息、房间等）。

```
              ┌───────────────┐
 用户 ───────>│   反向代理     │ (TLS 终止)
              └───────┬───────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼────┐  ┌────▼─────┐  ┌──▼──────────┐
    │ Pasion  │  │  Palpo   │  │   静态资源   │
    │ (认证)  │  │ (Matrix) │  │             │
    │  :8080  │  │  :8008   │  │             │
    └────┬────┘  └──────────┘  └─────────────┘
         │
    ┌────▼──────┐
    │ PostgreSQL │
    └───────────┘
```

### Palpo 服务器侧配置

在 Palpo 中配置 OIDC 委托，将认证交给 Pasion 处理：

```yaml
experimental_features:
  msc3861:
    enabled: true
    issuer: https://auth.example.com/
    client_id: 0000000000000000000PALPO
    client_auth_method: client_secret_basic
    client_secret: "你的密钥"
    admin_token: "管理员令牌"
    account_management_url: "https://auth.example.com/account/"
```

## CLI 命令参考

| 命令 | 说明 |
|------|------|
| `pasion server -c config.yaml` | 启动 HTTP 服务（默认命令） |
| `pasion config generate` | 生成默认配置文件 |
| `pasion config check -c config.yaml` | 校验配置文件 |
| `pasion config sync -c config.yaml` | 将 OAuth 客户端/上游提供商同步到数据库 |
| `pasion database migrate -c config.yaml` | 手动执行数据库迁移 |
| `pasion manage register-user` | 创建用户 |
| `pasion manage set-password` | 设置/重置用户密码 |
| `pasion manage promote-user` | 提升用户为管理员 |
| `pasion worker -c config.yaml` | 单独运行后台任务 worker |
| `pasion doctor -c config.yaml` | 诊断部署健康状态 |

### 服务启动选项

```bash
pasion server -c config.yaml                # 完整启动（默认）
pasion server -c config.yaml --no-worker    # 仅 HTTP 服务，不启动后台 worker
pasion server -c config.yaml --no-migrate   # 跳过自动数据库迁移
pasion server -c config.yaml --no-sync      # 跳过配置同步到数据库
```

## 上游 SSO 提供商

Pasion 支持与外部身份提供商联合登录。任何标准 OIDC 提供商均可开箱即用，同时为以下中国平台提供了专用适配：

| 提供商 | `token_endpoint_auth_method` | 说明 |
|--------|------------------------------|------|
| Google、GitHub、GitLab 等 | `client_secret_post` / `client_secret_basic` | 标准 OIDC |
| Apple | `sign_in_with_apple` | Apple 专用 JWT 客户端密钥 |
| QQ | `qq_connect` | 非标准 token + 独立 OpenID 接口 |
| 微信 | `wechat` | 使用 `appid`/`secret`，token 包含 `openid` |
| 企业微信 | `wecom` | 企业 access_token + 用户身份解析 |
| 飞书 | `feishu` | 两步获取：先 app_access_token，再用户 token |
| Lark | `lark` | 国际版飞书，相同流程不同端点 |
| 钉钉 | `dingtalk` | JSON 请求体 + 自定义 access token 头 |

详细的提供商配置示例请参阅 [SSO 配置指南](docs/zh/setup/sso.md)。

## 生产部署

生产环境建议分离 HTTP 服务和后台 worker，可独立水平扩展：

```bash
# HTTP 服务（可负载均衡）
pasion server --no-worker -c config.yaml

# 后台 worker（可多实例运行）
pasion worker -c config.yaml
```

服务暴露的关键端点：

| 端点 | 用途 |
|------|------|
| `/health` | 健康检查 |
| `/metrics` | Prometheus 指标 |
| `/.well-known/openid-configuration` | OIDC 发现 |
| `/oauth2/authorize` | OAuth 2.0 授权 |
| `/oauth2/token` | Token 端点 |
| `/api/admin/v1/*` | 管理 API |

## 文档

完整文档请访问 <https://palpo-im.github.io/pasion/>。

| 章节 | 说明 |
|------|------|
| [安装部署](docs/zh/setup/installation.md) | 安装和配置 Pasion |
| [基础配置](docs/zh/setup/general.md) | 基础配置指引 |
| [数据库](docs/zh/setup/database.md) | 数据库配置与迁移 |
| [Homeserver 集成](docs/zh/setup/homeserver.md) | Palpo / Matrix 集成 |
| [反向代理](docs/zh/setup/reverse-proxy.md) | nginx / Caddy 配置 |
| [SSO 配置](docs/zh/setup/sso.md) | 上游身份提供商配置 |
| [配置参考](docs/zh/reference/configuration.md) | 完整配置选项 |
| [CLI 参考](docs/zh/reference/cli/) | 命令行工具文档 |
| [管理 API](docs/zh/topics/admin-api.md) | 通过 API 管理用户和会话 |
| [架构设计](docs/zh/development/architecture.md) | 内部设计和 crate 结构 |
| [参与贡献](docs/zh/development/contributing.md) | 如何参与项目贡献 |

## 系统要求

- **PostgreSQL** 17 或更高版本
- **Palpo** homeserver 0.2.1 或更高版本（或任何兼容的 Matrix homeserver）
- 反向代理（nginx、Caddy 等）用于 TLS 终止

## 许可证

详见 [LICENSE](LICENSE)。
