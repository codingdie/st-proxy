# ST-Proxy 优化任务清单

## 🔴 P0 - 严重逻辑错误（Critical Logic Bugs）

| 问题 | 位置 | 描述 | 影响 | 状态 |
|------|------|------|------|------|
| 隧道选择条件错误 | [proxy_session.cpp:68](src/core/proxy_session.cpp#L68) | `try_connect_index < 1` 应改为 `< selected_tunnels.size()`，导致只尝试第一个隧道 | 隧道回退机制完全失效 | ✅ 已完成 |
| 质量分析器排序错误 | [quality_analyzer.cpp:269](src/core/analyzer/quality_analyzer.cpp#L269) | `record_a.first_package_failed()` 重复使用，应为 `record_b` | 隧道质量排序失效 | ✅ 已完成 |
| try_analyze 循环条件错误 | [quality_analyzer.cpp:301](src/core/analyzer/quality_analyzer.cpp#L301) | 循环条件 `i < 1` 错误，应为 `i < record.queue_limit()` | 网络质量测试永远不触发 | ✅ 已完成 |

## 🔴 P1 - 严重并发/内存问题（Critical Concurrency/Memory Issues）

| 问题 | 位置 | 描述 | 影响 | 状态 |
|------|------|------|------|------|
| session_manager 竞态条件 | [session_manager.cpp:32](src/core/session_manager.cpp#L32) | `add()` 在主线程调用 `start()`，但异步添加到 map；`monitor_session()` 无锁遍历 | 可能导致崩溃或 session 丢失 | ✅ 已完成 |
| Lambda 悬垂指针风险 | [proxy_session.cpp:70-78](src/core/proxy_session.cpp#L70-L78) | Lambda 按值捕获 `this`，异步回调时 session 可能已销毁 | 访问已释放内存，导致崩溃 | ✅ 已完成 |

## 🟡 P3 - 性能优化（Performance Optimizations）

| 问题 | 位置 | 描述 | 影响 | 状态 |
|------|------|------|------|------|
| 频繁的数据库访问 | [quality_analyzer.cpp:231-290](src/core/analyzer/quality_analyzer.cpp#L231-L290) | 每次选择隧道需要 2N 次同步 LevelDB 读取 | 高并发时延迟增加 | ⏳ 待优化 |
| macOS 端口分配低效 | [proxy_session.cpp:221-226](src/core/proxy_session.cpp#L221-L226) | 随机猜测端口，最多尝试 1000 次 | macOS 上连接建立慢 | ⏳ 待优化 |
| monitor_session 轮询 | [session_manager.cpp:39-44](src/core/session_manager.cpp#L39-L44) | 每 10 秒遍历所有 session | 高并发时 CPU 开销大 | ⏳ 待优化 |

## 🔵 P4 - 代码质量改进（Code Quality Improvements）

| 问题 | 位置 | 描述 | 影响 | 状态 |
|------|------|------|------|------|
| 内存管理不一致 | 全局 | 混用裸指针和智能指针，所有权语义不清晰 | 代码可维护性差 | ⏳ 待改进 |
| 缺少单元测试覆盖 | 全局 | 核心逻辑（隧道选择、质量分析）缺少测试 | 回归风险高 | ⏳ 待改进 |

---

## 修复状态说明

- ⏳ 待修复：尚未开始
- 🚧 进行中：正在修复
- ✅ 已完成：已修复并测试
- ⏸️ 暂缓：暂时搁置
- ❌ 已取消：不再修复

## 修复建议顺序

1. **第一批（P0）**：修复三个严重逻辑错误，都是简单的一行修改
   - 隧道选择条件错误
   - 质量分析器排序错误
   - try_analyze 循环条件错误

2. **第二批（P1）**：修复并发和内存安全问题
   - session_manager 竞态条件
   - Lambda 悬垂指针风险

3. **第三批（P3）**：性能优化
   - 添加质量分析器缓存
   - 优化端口分配策略
   - 改进 session 监控机制

4. **第四批（P4）**：代码质量提升
   - 统一内存管理策略
   - 增加单元测试覆盖率

---

**最后更新时间**: 2026-02-12
