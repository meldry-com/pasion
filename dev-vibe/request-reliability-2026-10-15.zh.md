# Pasion 接口等待问题检查

发现两类相似问题，已修复：

1. 前端统一 REST 请求没有截止时间，登录页 /auth/providers、账号页 /viewer 等接口一直 pending 时，资源一直为 None，页面一直加载。已增加初始化 GET 5 秒、普通 GET 15 秒、写请求 60 秒截止；计时覆盖错误和成功响应的正文读取。登录与账号入口支持错误后手动重试，不自动重放写操作。
2. 队列退出和测试 drain 流程占用 pooled connection 后等待任务结束，而任务可能再次访问连接池。现先等待任务完成，再获取连接更新任务结果。单连接池也可以正常完成。

另外，连接池的阶段超时没有覆盖 pre-recycle hook。现提供完整 checkout 总截止（生产默认 30 秒，可通过既有连接超时配置调整），清理钩子与 BEGIN 各自 5 秒，健康检查全链路 5 秒。队列 leader 正常调度使用同一连接执行操作，未发现原 Paloud 的持锁后二次 checkout 问题。

验证使用独立临时 PostgreSQL 18 容器和本地真实 WASM 页面，不接触生产数据库。已通过：

- `cargo check -p pasion-backend -p pasion-tasks -p pasion-frontend --locked`。
- 连接池回归 1 项，覆盖耗尽、pre-recycle 永不完成、post-create 永不完成三种场景。
- `cargo test -p pasion-tasks --lib` 全部 7 项通过，其中单连接回归验证任务再次取连接并记录 completed。
- 原有 `test_diesel_pool_recycles_connections_back_to_a_clean_session` 通过，确认未完成事务仍被清理。
- 6 项真实 WASM 浏览器回归通过。初始化接口约 5.3 秒、普通查询约 15.1 秒结束等待；响应头停滞、成功正文停滞、503 正文停滞均能取消 fetch，入口页手动重试恢复，无自动重试、无页面崩溃。
- pinned nightly rustfmt、`git diff --check`、测试脚本语法检查通过。定向 Clippy 完成，既有 register.rs 数值转换及 registration.rs 大错误类型警告仍存在；本次不扩展修改这些路径。

本地 dx 0.7.9 与项目 Dioxus 0.7.5 产生版本提示，wasm-opt 在 Windows 返回 0xc0000409；Rust WASM 编译、wasm-bindgen 和静态产物生成完成，以上浏览器回归运行这些实际产物。这不能作为发布镜像或优化构建验证。

检查范围是已识别的等待路径，没有设置全局 SQL statement_timeout，multipart 头像上传仍是独立请求路径；未执行 Pasion 生产部署。
