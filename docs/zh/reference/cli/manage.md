# `manage`

用户和账户管理命令。

## 用户管理

### 注册用户

```bash
pasion manage register-user -c config.yaml <用户名>
```

### 设置密码

```bash
pasion manage set-password -c config.yaml <用户名>
```

### 添加邮箱

```bash
pasion manage add-email -c config.yaml <用户名> <邮箱>
```

### 验证邮箱

```bash
pasion manage verify-email -c config.yaml <用户名> <邮箱>
```

## 管理员管理

### 提升为管理员

```bash
pasion manage promote-admin -c config.yaml <用户名>
```

### 撤销管理员权限

```bash
pasion manage demote-admin -c config.yaml <用户名>
```

### 列出所有管理员

```bash
pasion manage list-admin-users -c config.yaml
```

## 用户状态

### 锁定用户

```bash
pasion manage lock-user -c config.yaml <用户名>
```

### 解锁用户

```bash
pasion manage unlock-user -c config.yaml <用户名>
```

## 会话管理

### 终止用户的所有会话

```bash
pasion manage kill-sessions -c config.yaml <用户名>
```

## 令牌管理

### 签发兼容性令牌

为用户签发一个旧版 Matrix 兼容令牌：

```bash
pasion manage issue-compatibility-token -c config.yaml <用户名>
```

### 签发注册令牌

生成一次性注册令牌：

```bash
pasion manage issue-user-registration-token -c config.yaml
```

## 批量操作

### 同步所有用户到 Homeserver

将 Pasion 中的所有用户同步到 Matrix homeserver：

```bash
pasion manage provision-all-users -c config.yaml
```
