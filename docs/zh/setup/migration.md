# 从现有 Homeserver 迁移

如果你已有一个使用传统认证方式的 Matrix homeserver，Pasion 提供了 `syn2mas` 工具来迁移现有用户和密码。

## 迁移前准备

1. **备份数据库** — 在开始迁移前，务必备份你的 homeserver 数据库和 Pasion 数据库
2. **规划停机时间** — 迁移过程中用户无法登录
3. **审查用户数据** — 了解哪些用户需要迁移，哪些可以跳过

## 不支持的场景

以下认证方式无法直接迁移：

- SAML 认证
- LDAP 认证
- 自定义认证插件

如果你使用这些方式，需要先配置对应的上游 OIDC 提供商（如 Keycloak、Dex），然后通过该提供商进行认证。

## 迁移步骤

### 1. 检查兼容性

```bash
pasion syn2mas check -c syn2mas-config.yaml
```

此命令会检查源数据库中的用户数据，报告可能的问题。

### 2. 试运行

```bash
pasion syn2mas migrate --dry-run -c syn2mas-config.yaml
```

试运行不会修改任何数据，但会显示将要执行的操作。

### 3. 执行迁移

```bash
pasion syn2mas migrate -c syn2mas-config.yaml
```

### 4. 验证迁移结果

迁移完成后：
- 检查用户数量是否与预期一致
- 测试几个用户的登录功能
- 验证密码登录是否正常工作

## 密码迁移

Pasion 支持从 bcrypt 格式迁移密码哈希。用户的现有密码在迁移后仍然有效，无需重置密码。

当用户首次使用旧密码登录时，Pasion 会自动将密码哈希升级为 Argon2id 格式。
