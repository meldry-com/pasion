# 使用管理 API

Pasion 提供了 RESTful 管理 API，用于管理用户、会话和 OAuth 2.0 客户端。

## API 文档

完整的 API 文档以 OpenAPI 规范提供，可在 [API 参考](../api/index.html) 中查看。

## 认证方式

管理 API 支持两种认证方式：

### 1. 交互式认证

使用浏览器会话进行认证。适合通过 Web 界面手动管理：

```bash
# 先通过设备码流程获取令牌
pasion manage issue-compatibility-token --scope "urn:pasion:admin" <user_id>
```

### 2. OAuth 2.0 令牌

管理作用域只授予管理员用户（`admin` 标志为 `true`）。`client_credentials` 授权没有用户，**无法**获得管理 API 访问权限。

面向自动化工具，请由已有管理员通过 `POST /api/admin/v1/personal-sessions` 为某个管理员用户创建个人访问令牌：

```json
{
  "actor_user_id": "管理员用户ID",
  "human_name": "Provisioning bot",
  "scope": "urn:pasion:admin",
  "expires_in": 31536000
}
```

该用户一旦被撤销管理员、锁定或停用，令牌立即失效。建议为每个工具单独建一个管理员用户。

## 响应格式

管理 API 遵循 JSON API 规范，所有响应使用统一的 JSON 格式。

### 成功响应

```json
{
  "data": {
    "type": "user",
    "id": "01HFRQFT5QFBM3Y5BHNFHMP6M0",
    "attributes": {
      "username": "alice"
    }
  }
}
```

### 分页

列表端点使用基于游标的分页：

```bash
# 获取前 10 个用户
curl "https://auth.example.com/api/admin/v1/users?page[first]=10"

# 使用游标获取下一页
curl "https://auth.example.com/api/admin/v1/users?page[first]=10&page[after]=游标值"
```

响应中包含分页信息：

```json
{
  "page": {
    "has_next_page": true,
    "has_previous_page": false,
    "start_cursor": "...",
    "end_cursor": "..."
  }
}
```

## 常用操作

### 列出所有用户

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/users
```

### 锁定用户

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/users/$USER_ID/lock
```

### 终止用户的所有会话

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/users/$USER_ID/sessions/kill
```
