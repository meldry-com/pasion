# API 等待与队列连接池可靠性

更新：2026-10-15。

- 从 Paloud/Hagency 的接口 pending 事故排查扩展至 Pasion；这是源码审计和隔离环境回归，未证明 Pasion 生产环境已发生同一事故。
- Pasion 的 leader duties 在锁住的同一连接执行数据库操作，没有发现 Paloud 的运行时调度器持锁后再次取连接路径。但 shutdown_worker / process_all_jobs_in_tests 原来持有业务连接等待任务完成，任务又可能需要同一池；小池下可能卡住或任务取连接失败。现为不持连接等待任务，仅在记录已完成任务结果时取连接；process_jobs 不再提供阻塞等待模式。
- pg::get_connection 对完整 pool.get（等待、建立、回收及 hooks）设总截止，采用池的 wait timeout，未配置时 5 秒。生产默认 database.connect_timeout 为 30 秒。PgRepositoryFactory 和队列入口使用该函数；BEGIN 单独 5 秒。生产 session cleanup hook 5 秒；health checkout + SELECT 1 总计 5 秒。
- 前端统一 reqwest 请求：GET /site-config、/viewer、/auth/providers 为 5 秒，其他 GET 15 秒，写操作 60 秒，无自动重试。reqwest 0.13.4 WASM AbortGuard 随 Response 保持至正文读取结束，已通过实际浏览器模拟响应头/正文停滞验证。账号和登录入口失败显示错误并可手动 Try again。
- 此变更不为所有 SQL 查询设置 statement_timeout；不包含独立 multipart 头像上传路径。不能把这些定向保护描述成所有后台操作均有截止时间。
- 数据库回归：`cargo test -p pasion-data checkout_deadline_covers_pool_exhaustion_and_hooks`；`cargo test -p pasion-tasks --lib`。DATABASE_URL 只能指向测试数据库，任务测试会创建隔离数据库并执行现有 migrations；未修改 schema.rs/migrations。
- 浏览器回归：`node misc/test-request-timeouts.cjs`，见脚本头部 Playwright 安装说明；运行前先构建 pasion-frontend。覆盖 6 项实际 WASM 场景，不依赖生产账号。
- 本次只检查/修复并提交 Pasion 源码，未构建发布镜像或部署 Pasion。
