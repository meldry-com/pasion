# `config`

配置文件管理命令。

## `config generate`

生成一个带有合理默认值的配置文件：

```bash
pasion-cli config generate > config.yaml
```

## `config check`

验证配置文件的语法和语义正确性：

```bash
pasion-cli config check -c config.yaml
```

## `config dump`

输出合并后的完整配置（包括所有默认值）：

```bash
pasion-cli config dump -c config.yaml
```

## `config sync`

将配置文件中的 OAuth 2.0 客户端和上游提供商定义同步到数据库：

```bash
pasion-cli config sync -c config.yaml

# 试运行（不实际修改）
pasion-cli config sync --dry-run -c config.yaml

# 删除数据库中不在配置文件中的项目
pasion-cli config sync --prune -c config.yaml
```
