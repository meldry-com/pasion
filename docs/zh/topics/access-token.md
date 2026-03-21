# 获取访问令牌

本页介绍如何通过命令行获取 Pasion 管理 API 的访问令牌。

## 使用设备码流程

最简单的方式是使用设备码授权流程（Device Code Grant）：

```bash
# 请求管理 API 的访问令牌
GRANT=$(curl -s -X POST https://auth.example.com/oauth2/device/authorize \
  -d "client_id=你的客户端ID" \
  -d "scope=urn:mas:admin")

# 显示用户验证 URL
echo "请在浏览器中打开: $(echo $GRANT | jq -r '.verification_uri_complete')"

# 等待用户完成授权后获取令牌
TOKEN=$(curl -s -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=你的客户端ID" \
  -d "device_code=$(echo $GRANT | jq -r '.device_code')" \
  | jq -r '.access_token')

echo "访问令牌: $TOKEN"
```

## 使用客户端凭据流程

如果你有配置好的 OAuth 2.0 客户端：

```bash
TOKEN=$(curl -s -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=你的客户端ID" \
  -d "client_secret=你的客户端密钥" \
  -d "scope=urn:mas:admin" \
  | jq -r '.access_token')
```

## 常用作用域

| 作用域 | 说明 |
|--------|------|
| `urn:mas:admin` | Pasion 管理 API 完全访问权限 |
| `urn:palpo:admin:api` | Palpo 管理 API 访问权限 |
| `urn:matrix:client:api:*` | Matrix 客户端 API 完全访问权限 |

## 注意事项

- 访问令牌有过期时间（默认 5 分钟），过期后需要重新获取
- 管理 API 的访问令牌应安全存储，不要泄露给未授权的用户
- 建议在脚本中使用客户端凭据流程，在交互式场景中使用设备码流程
