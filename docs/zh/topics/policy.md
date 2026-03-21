# 策略引擎

Pasion 内置了一个基于 [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) 的策略引擎，用于控制用户注册、客户端注册和授权请求等行为。

## 工作原理

策略以 WebAssembly (WASM) 模块的形式加载，使用 [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) 语言编写。Pasion 在关键操作发生时会查询策略引擎，根据返回结果决定是否允许该操作。

## 策略评估点

策略引擎在以下场景被调用：

| 评估点 | 说明 |
|--------|------|
| 用户注册 | 控制是否允许新用户注册，可以验证用户名、邮箱等属性 |
| 客户端注册 | 控制 OAuth 2.0 客户端动态注册 |
| 授权请求 | 控制是否授予特定的 OAuth 2.0 作用域 |

## 默认策略

Pasion 自带一个默认策略，实现了以下规则：

- 允许所有用户注册（除非被配置禁用）
- 允许所有客户端注册
- 管理 API 作用域仅授予配置的管理客户端

## 自定义策略

你可以通过配置文件指定自定义策略 WASM 文件：

```yaml
policy:
  wasm_module: /path/to/custom-policy.wasm
  data:
    admin_clients:
      - "你的管理客户端ID"
```

### 编写自定义策略

策略使用 Rego 语言编写，然后编译为 WASM：

```rego
package register

# 禁止用户名中包含 "admin"
violation contains {"msg": "reserved username"} if {
    contains(input.registration_request.username, "admin")
}
```

编译为 WASM：

```bash
opa build -t wasm -e 'register/violation' policy.rego
```

## 策略数据

可以通过配置文件或管理 API 向策略引擎传递数据。这些数据可在策略规则中引用：

```yaml
policy:
  data:
    admin_clients:
      - "client_id_1"
    allowed_domains:
      - "example.com"
```

在策略中使用：

```rego
package register

violation contains {"msg": "email domain not allowed"} if {
    email := input.registration_request.email
    domain := split(email, "@")[1]
    not domain in data.allowed_domains
}
```
