# OAuth 2.0 作用域

Pasion 支持以下 OAuth 2.0 作用域（scope）。客户端在请求授权时可以指定一个或多个作用域。

## OpenID Connect 标准作用域

| 作用域 | 说明 |
|--------|------|
| `openid` | OpenID Connect 基本身份认证（必须） |
| `profile` | 获取用户的基本资料（显示名称等） |
| `email` | 获取用户的电子邮箱地址 |

## Matrix 相关作用域（MSC2967）

| 作用域 | 说明 |
|--------|------|
| `urn:matrix:client:api:*` | Matrix 客户端 API 完全访问权限 |
| `urn:matrix:client:api:guest` | Matrix 客户端 API 访客权限 |

## Palpo 专属作用域

| 作用域 | 说明 |
|--------|------|
| `urn:palpo:admin:api` | Palpo 管理 API 访问权限 |

## Pasion 管理作用域

| 作用域 | 说明 |
|--------|------|
| `urn:pasion:admin` | Pasion 管理 API 完全访问权限（旧版 `urn:mas:admin` 仍兼容支持） |
| `urn:mas:admin:read` | Pasion 管理 API 只读权限 |

## 作用域与策略

### 管理作用域

管理作用域（`urn:pasion:admin`、`urn:mas:admin`、`urn:palpo:admin:*`、`urn:synapse:admin:*`）只授予管理员用户，即 `admin` 标志（数据库字段 `can_request_admin`）为 `true` 的用户。该检查内置于 Pasion，策略无法放宽：

- 登录用户不是管理员时，同意页直接拒绝；
- 授权码、设备码、刷新令牌兑换时会重新检查用户，期间被降权的用户拿不到（也保不住）令牌；
- `client_credentials` 授权没有用户可检查，永远拿不到管理作用域；
- 每次调用管理 API 都会重新检查该标志，撤销后已签发的令牌立即失效。

该标志变更时会同步到 homeserver（Palpo `is_admin`）。可通过管理 API（`PATCH /api/admin/v1/users/{id}`，`{"admin": true|false}`）或 CLI `manage promote-admin` / `manage demote-admin` 授予与撤销。最后一个有效管理员不能被降权、锁定或停用。

其他作用域默认允许所有客户端请求，你可以通过[自定义策略](../topics/policy.md)修改这些规则。
