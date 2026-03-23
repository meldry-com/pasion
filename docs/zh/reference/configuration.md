# 配置文件参考

本页列出 Pasion 配置文件的所有可用选项。完整的英文配置参考请查看[英文版本](../../reference/configuration.md)。

## 配置文件格式

Pasion 使用 YAML 格式的配置文件。通过 `-c` 或 `--config` 参数指定：

```bash
pasion server -c config.yaml
```

## 主要配置段

### `http` — HTTP 服务器

```yaml
http:
  # 对外公开的基础 URL（必须包含协议和域名）
  public_base: https://auth.example.com/

  # 可选的签发者 URL（用于 OIDC 发现）
  # issuer: https://auth.example.com/

  # 监听器配置
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      proxy_protocol: false
      resources:
        - name: discovery    # OIDC 发现端点
        - name: human        # 用户界面（登录、注册等）
        - name: oauth        # OAuth 2.0 端点
        - name: compat       # 旧版 Matrix 登录兼容层
        - name: graphql      # GraphQL API
        - name: assets       # 静态资源
          path: /path/to/frontend/dist/
        - name: health       # 健康检查端点

  # 信任的代理 IP 范围
  trusted_proxies:
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - 127.0.0.0/8
    - "::1/128"
```

### `database` — 数据库连接

```yaml
database:
  uri: postgresql://user:password@localhost/pasion
  max_connections: 10
  min_connections: 0
  connect_timeout: 30
```

### `matrix` — Matrix Homeserver

```yaml
matrix:
  homeserver: example.com          # Matrix 服务器名称
  secret: "共享密钥"                # 与 homeserver 的共享密钥
  endpoint: "https://matrix.example.com"  # homeserver API 地址
```

### `secrets` — 密钥和加密

```yaml
secrets:
  encryption: "32字节的加密密钥（Base64编码）"
  keys:
    - kid: "key-id-1"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
```

### `passwords` — 密码策略

```yaml
passwords:
  enabled: true              # 是否启用密码登录
  minimum_complexity: 3      # 最低密码复杂度（0-4）
  schemes:
    - version: 1
      algorithm: argon2id    # 密码哈希算法
```

### `email` — 邮件发送

```yaml
email:
  from: '"Pasion" <noreply@example.com>'
  reply_to: '"Support" <support@example.com>'
  transport: smtp
  mode: starttls
  hostname: smtp.example.com
  port: 587
  username: "smtp_user"
  password: "smtp_password"
```

### `telemetry` — 可观测性

```yaml
telemetry:
  tracing:
    exporter: otlp           # none / stdout / otlp
    endpoint: "https://otel-collector:4318"
    propagators:
      - tracecontext
      - baggage
  metrics:
    exporter: prometheus      # none / stdout / otlp / prometheus
```

### `rate_limiting` — 速率限制

```yaml
rate_limiting:
  login:
    burst: 3                  # 突发允许次数
    per_second: 0.5           # 每秒允许次数
  registration:
    burst: 3
    per_second: 0.1
```

### `captcha` — 验证码

```yaml
captcha:
  service: recaptcha_v2       # recaptcha_v2 / cloudflare_turnstile / hcaptcha
  site_key: "你的站点密钥"
  secret_key: "你的密钥"
```

更多配置选项请参阅[完整英文参考文档](../../reference/configuration.md)。
