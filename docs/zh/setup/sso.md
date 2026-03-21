# 配置上游 SSO 提供商

Pasion 支持通过上游 OpenID Connect (OIDC) 提供商实现联合登录（Social Login / SSO）。这允许用户使用已有的第三方账户（如 Google、GitHub 等）登录 Matrix。

## 基本概念

- **上游提供商（Upstream Provider）** — 外部身份提供商（如 Google、GitHub、Keycloak 等）
- **用户属性映射（Attribute Mapping）** — 使用 Jinja2 模板将上游提供商的用户信息映射到 Matrix 用户属性
- **账户关联（Account Linking）** — 将上游身份与本地 Matrix 账户关联

## 配置格式

在 Pasion 配置文件中添加上游提供商：

```yaml
upstream_oauth2:
  providers:
    - id: "01HFRQFT5QFBM3Y5BHNFHMP6M0"  # 唯一 ID（ULID 格式）
      issuer: "https://accounts.google.com/"
      client_id: "你的客户端ID"
      client_secret: "你的客户端密钥"
      scope: "openid email profile"
      claims_imports:
        localpart:
          action: require
          template: "{{ user.preferred_username }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```

## 常见提供商配置

### Google

```yaml
- id: "01HFRQFT5QFBM3Y5BHNFHMP6M0"
  issuer: "https://accounts.google.com/"
  client_id: "你的Google客户端ID.apps.googleusercontent.com"
  client_secret: "你的客户端密钥"
  scope: "openid email profile"
```

### GitHub

```yaml
- id: "01HFRQFT5QFBM3Y5BHNFHMP6M1"
  issuer: "https://github.com/"
  token_endpoint_auth_method: client_secret_post
  client_id: "你的GitHub客户端ID"
  client_secret: "你的客户端密钥"
  scope: "openid"
```

### GitLab

```yaml
- id: "01HFRQFT5QFBM3Y5BHNFHMP6M2"
  issuer: "https://gitlab.com/"
  client_id: "你的GitLab客户端ID"
  client_secret: "你的客户端密钥"
  scope: "openid email profile"
```

## 用户属性映射

`claims_imports` 部分定义了如何将上游提供商的用户信息映射到本地用户属性：

| 属性 | 说明 |
|------|------|
| `localpart` | Matrix 用户名（如 `@username:example.com` 中的 `username`） |
| `displayname` | 用户显示名称 |
| `email` | 电子邮箱地址 |

每个属性支持以下 `action`：

| 动作 | 说明 |
|------|------|
| `require` | 必须从上游提供商获取，否则登录失败 |
| `suggest` | 从上游获取并建议使用，用户可以修改 |
| `force` | 强制使用上游提供商的值，每次登录都会更新 |
| `ignore` | 忽略上游提供商的值 |

## 故障排查

- **发现失败** — 确保 `issuer` URL 正确，且 `/.well-known/openid-configuration` 端点可访问
- **令牌交换失败** — 检查 `client_id` 和 `client_secret` 是否正确
- **属性映射错误** — 检查 Jinja2 模板语法，确保引用的字段在上游提供商的 ID Token 中存在
