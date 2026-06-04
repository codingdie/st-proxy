# st-proxy common 同步与外围适配设计

## 目标

将 `st-dns/src/common` 完整同步覆盖到 `st-proxy/src/common`，不再修改 `st-proxy` 的 `common` 代码；随后仅通过修改 `st-proxy` 的非 `common` 代码完成编译、测试与行为适配。

用户已明确确认：

1. 同步方式为直接覆盖，而不是局部挑选。
2. 即使会覆盖 `st-proxy/src/common` 中当前未提交的差异，也按 `st-dns` 版本为准。
3. 后续不得再手改 `st-proxy/src/common`，只能修改外围代码适配。

## 当前范围

当前 `st-dns/src/common` 与 `st-proxy/src/common` 的差异集中在 7 个文件：

1. `src/common/main/console/udp_console.cpp`
2. `src/common/main/console/udp_console.h`
3. `src/common/main/utils/area_ip.cpp`
4. `src/common/main/utils/area_ip.h`
5. `src/common/main/utils/logger.cpp`
6. `src/common/main/utils/logger.h`
7. `src/common/test/unit_tests.cpp`

虽然当前 diff 只显示这 7 个文件不同，本次执行仍以“完整目录同步”为准，保证 `st-proxy/src/common` 与 `st-dns/src/common` 后续保持单一来源。

## 设计原则

### 单一来源

`st-dns/src/common` 作为本次同步后的唯一来源。同步完成后，`st-proxy/src/common` 视作外部输入，不再在当前任务中修改。

### 适配边界

所有适配仅发生在以下区域：

1. `st-proxy/src/core`
2. `st-proxy/src/test`
3. `st-proxy/CMakeLists.txt`
4. 必要时 OpenWrt 打包层或配置层

### 最小改动

外围适配只处理因 `common` 接口、生命周期、日志/APM 行为变化带来的编译与运行问题，不借机做无关重构。

## 执行方案

### 方案 A：直接全量覆盖并增量修复外围

先把 `st-dns/src/common` 整体复制到 `st-proxy/src/common`，再以构建错误和测试失败为驱动逐步修复外围代码。

优点：

1. 最符合“同步 common”的目标。
2. 同步边界最清楚，后续维护成本最低。
3. 能避免只同步部分文件导致的继续漂移。

代价：

1. 第一轮编译报错可能较多。
2. 某些测试或运行时行为会暴露出更深的外围依赖。

### 方案 B：只同步当前有差异的 7 个文件

优点是改动面小；缺点是 `common` 仍不是严格单一来源，不符合本次目标。

### 方案 C：保留当前 common 差异并做兼容层

优点是短期风险较小；缺点是违背“common 不动、外围适配”的目标，也会留下长期维护负担。

## 推荐方案

采用方案 A。

理由：

1. 用户已经接受直接覆盖现有 `common` 差异。
2. `common` 应作为共享基础层，优先建立统一来源而不是继续分叉。
3. 当前任务的技术风险主要在外围适配，而不是同步动作本身。

## 具体步骤

### 第一步：同步 common

将 `st-dns/src/common` 覆盖到 `st-proxy/src/common`。同步后不再修改该目录。

### 第二步：编译收敛

运行构建，记录第一轮错误，并按以下顺序修复：

1. 头文件和函数签名不匹配
2. 生命周期与初始化流程变化
3. 日志/APM 调用方式变化
4. 单元测试辅助代码或 fixture 变化

### 第三步：运行时/测试适配

如果构建通过，再运行相关测试，处理：

1. 编译后链接问题
2. 测试初始化/清理流程变化
3. 行为断言变化

## 预期适配点

基于当前差异，第一批高概率适配点包括：

1. `logger` 生命周期、定时调度与 APM 状态管理的调用方式变化
2. `area_ip` 的接口、行为或加载路径变化
3. `udp_console` 的接口或调用点变化
4. `common` 测试入口变化对 `st-proxy` 测试编译的影响

这些都应由 `st-proxy` 的 `core`/`test` 层消化，而不是回改 `common`。

## 错误处理

如果同步后发现以下情况，则停止继续扩大改动面，并向用户明确报告：

1. `st-dns` 的 `common` 隐含依赖了 `st-dns` 专属类型，无法通过外围适配消除
2. OpenWrt 构建层需要同步额外非 `common` 文件才能继续
3. 当前工作区中已有未提交改动与同步结果发生不可分辨冲突

在这些情况下，优先给出最小补充设计，而不是直接继续盲改。

## 测试与验证

至少执行以下验证：

1. `cmake --build build`
2. 相关单元测试
3. 若条件允许，再执行 `ctest --output-on-failure -j1`

如果某些集成测试仍受外部网络、权限或环境限制影响，需要明确标注“代码适配完成，但环境限制导致无法完全验证”。

## 成功标准

满足以下条件视为完成：

1. `st-proxy/src/common` 与 `st-dns/src/common` 完成同步
2. 当前任务中不再修改 `st-proxy/src/common`
3. `st-proxy` 非 `common` 代码完成必要适配
4. 项目能够成功构建
5. 相关测试结果被明确记录
