# Pasion 改造任务清单

更新时间：2026-03-30

说明：

- 本清单根据 [`_codex.md`](/e:/Works/taidge/pasion/_codex.md) 拆解。
- 只把“可验证、可勾选”的任务放进来。
- 已经完成并验证过的项直接打勾。
- 后续按顺序推进，做完一项勾一项。

## P0：当前主线

### A. 注册与恢复 workflow 收口

- [x] 抽离 `account_recovery`，把恢复流程从 handler 迁到 shared workflow/service。
- [x] 抽离 registration finish preflight / completion service。
- [x] 抽离 registration status / email step / display-name step loader。
- [x] 将 REST `register` 的启动校验、policy、rate limit 和 registration 创建收口到 `account_registration`。
- [x] 让 legacy `verify_email` / `display_name` 页面走 shared registration service。
- [x] 为 shared registration service 引入结构化 validation issue 和 email availability mode。
- [x] 将 legacy `views/register/password.rs` 接到 shared registration service。
- [x] 将 registration 的 resend / verify-email / verify-phone / display-name / finish 结果映射进一步收成统一 workflow facade。
- [x] 引入显式 registration workflow state / event / deadline 代码模型。
- [x] 将 `rest/password.rs` 的 recovery 相关编排完全下沉到 `account_recovery`。
- [x] 将 `rest/emails.rs` / `account_contacts.rs` 完整收口到 shared contact workflow。

### B. 通知中心升级

- [x] 引入 `NotificationCenter` 边界。
- [x] 统一 notification dispatch 和 tasks 执行路径。
- [x] 打通短信验证码 job 执行链路。
- [x] 为 phone verification 加入独立 rate limit。
- [x] 设计 `notification_request` / `notification_delivery` / `notification_event_log` 数据模型。
- [x] 在 `storage` / `storage-pg` 落地通知投递 repository。
- [x] 加入 delivery retry / audit / provider binding。
- [x] 将业务层通知调用全部收口为“表达发什么”，不再关心渠道细节。

### C. Legacy 入口去编排化

- [x] 清理 `views/*` 对 repo / policy / limiter / task 的直接编排依赖。
- [ ] 清理 `rest/*` 中剩余的“查库 + 校验 + 状态推进 + 发任务”组合逻辑。
- [ ] 让 handler 保持为纯 HTTP adapter，只做请求解析与响应映射。

## P1：高优先级

### D. 数据模型与存储聚合重构

- [ ] 设计 workflow 相关新表：`workflow_instance` / `workflow_step` / `workflow_event` / `workflow_deadline` / `workflow_audit_log`。
- [ ] 设计通知相关新表：`notification_request` / `notification_delivery` / `notification_template_version` / `notification_preference` / `notification_provider_binding`。
- [ ] 设计账户聚合新表：`account_contact_point` / `account_identity_binding` / `account_security_event`。
- [ ] 调整 `storage` / `storage-pg` repository 边界，按业务聚合而不是按零散对象组织。

### E. Connector Platform

- [ ] 为 `matrix-palpo` 抽出 connector trait。
- [ ] 加入 provider registry / capability discovery / provisioning adapter。
- [ ] 将 `Palpo` 从系统骨架角色降级为一个 connector provider。
- [ ] 规划并预留 `connectors-core` / `connectors-matrix-palpo` / `connectors-upstream-oauth2` 结构。

### F. Admin API 与运营能力

- [ ] 将 admin API 从对象 CRUD 重构为运营动作 API。
- [ ] 增加通知模板发布、渠道状态、connector 健康检查、审计与报表能力。
- [ ] 将 `admin` handler 分层到更明确的 domain service。

### G. 前端 IA 设计

- [ ] 产出“用户门户 / 管理控制台”双 IA 草案。
- [ ] 重新规划 `frontend/src/pages` 的页面树。
- [ ] 重新规划通知中心、安全中心、联系方式管理、外部身份绑定的入口结构。

## P2：中优先级

### H. 配置、品牌、多租户

- [ ] 拆分平台级配置与租户级覆写配置。
- [ ] 设计 tenant / branding / policy override 结构。
- [ ] 打通模板、策略、品牌主题与通知配置。

### I. 文档与对外说明

- [ ] 重写 `README.md`。
- [ ] 重写 `README.zh.md`。
- [ ] 更新 `docs/zh/development/architecture.md`。
- [ ] 清理“认证服务分叉版”叙述，改成平台化叙述。

## P3：后置

### J. 基础设施清理

- [ ] 低收益 util 层统一。
- [ ] 低收益 rename 清理。
- [ ] 非关键基础库梳理与减债。

## 当前下一项

- [ ] 清理 `rest/*` 中剩余的“查库 + 校验 + 状态推进 + 发任务”组合逻辑。
