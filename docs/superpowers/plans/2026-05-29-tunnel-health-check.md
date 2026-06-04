# 隧道主动健康检查 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 增加隧道级别的定期主动健康检查，让挂掉的隧道在用户感知之前被标记 DOWN，避免每个连接都等 connect_timeout 才发现失败。

**Architecture:** 在 `net_test_manager` 中增加定时器，每 30 秒对每个隧道用其 `http_check_url`（缺省按区域选 baidu/google）做 TLS 握手探测。`stream_tunnel` 增加原子状态字段 `health_status`，`quality_analyzer::select_tunnels` 在打分时对 DOWN 隧道扣 100000 分使其排到最末（不直接剔除，避免全部 DOWN 时无可用隧道）。

**Tech Stack:** C++11, Boost.Asio, 已有的 `net_test_manager::tls_handshake_with_socks` / `tls_handshake` 探测能力。

---

## File Structure

| 文件 | 操作 | 职责 |
|---|---|---|
| `src/core/stream_tunnel.h` | 修改 | 增加 `health_status` 原子字段（UNKNOWN/UP/DOWN）、连续失败计数、helpers |
| `src/core/stream_tunnel.cpp` | 修改 | health_status 初始化 |
| `src/core/config.cpp` | 修改 | 解析时若 `http_check_url` 为空，按 area 设默认（CN/DIRECT → www.baidu.com:443，其他 → www.google.com:443） |
| `src/core/analyzer/net_test_manager.h` | 修改 | 增加 `start_tunnel_health_check()` 定时器、`check_tunnel_once()` 接口 |
| `src/core/analyzer/net_test_manager.cpp` | 修改 | 实现定时探测、解析 host 为 IP 后调 `tls_handshake_with_socks` / `tls_handshake`，根据结果更新 tunnel 健康状态 |
| `src/core/analyzer/quality_analyzer.cpp` | 修改 | `select_tunnels` 中 DOWN 状态扣 100000 分 |
| `src/core/console/proxy_console.cpp` | 修改 | 增加 `proxy tunnel health` 命令查看健康状态 |
| `src/test/unit/tunnel_health_check_test.cpp` | 创建 | 单元测试 |

---

## Task 1: 给 stream_tunnel 增加健康状态字段

**Files:**
- Modify: `src/core/stream_tunnel.h`
- Modify: `src/core/stream_tunnel.cpp`

- [ ] **Step 1: 修改 stream_tunnel.h，增加状态枚举和原子字段**

```cpp
//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_PROXY_StreamTunnel_H
#define ST_PROXY_StreamTunnel_H

#include "st.h"
#include <atomic>
#include <map>
#include <utility>
#include <vector>

enum tunnel_health_status {
    HEALTH_UNKNOWN = 0,
    HEALTH_UP = 1,
    HEALTH_DOWN = 2,
};

class stream_tunnel {
public:
    string type = "DIRECT";
    string ip;
    int port = 0;
    string area;
    vector<string> proxyAreas;
    set<string> whitelist;
    set<uint32_t> ip_whitelist;
    string http_check_url;

    // 健康检查相关
    std::atomic<int> health_status{HEALTH_UNKNOWN};
    std::atomic<uint32_t> consecutive_failures{0};
    std::atomic<uint64_t> last_check_time{0};
    std::atomic<uint32_t> last_check_cost{0};

    string id() const;

    stream_tunnel(const string &type, const string &ip, int port);

    bool in_whitelist(const string &domain);
    bool in_whitelist(const vector<string> &domains);
    bool in_whitelist(uint32_t input_ip);

    bool is_down() const { return health_status.load() == HEALTH_DOWN; }
    bool is_up() const { return health_status.load() == HEALTH_UP; }
};


#endif//ST_PROXY_StreamTunnel_H
```

- [ ] **Step 2: 编译验证**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`

- [ ] **Step 3: 提交**

```bash
git add src/core/stream_tunnel.h
git commit -m "feat(tunnel): 增加 stream_tunnel 健康状态字段"
```

---

## Task 2: 配置解析阶段填充默认 http_check_url

**Files:**
- Modify: `src/core/config.cpp`（在 `parse_stream_tunnel` 解析 http_check_url 之后追加默认值逻辑）

- [ ] **Step 1: 找到现有解析位置**

执行 `grep -n "http_check_url" src/core/config.cpp` 定位到 `st->http_check_url = tunnel.get("http_check_url", "");`

- [ ] **Step 2: 在该行之后追加默认值逻辑**

```cpp
st->http_check_url = tunnel.get("http_check_url", "");
if (st->http_check_url.empty()) {
    // CN 或 DIRECT 隧道默认探测 baidu，其他用 google
    if (st->area == "CN" || st->type == "DIRECT") {
        st->http_check_url = "https://www.baidu.com";
    } else {
        st->http_check_url = "https://www.google.com";
    }
}
```

- [ ] **Step 3: 编译验证**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`

- [ ] **Step 4: 提交**

```bash
git add src/core/config.cpp
git commit -m "feat(config): 为隧道未配置 http_check_url 填充默认探测目标"
```

---

## Task 3: net_test_manager 增加隧道健康探测能力

**Files:**
- Modify: `src/core/analyzer/net_test_manager.h`
- Modify: `src/core/analyzer/net_test_manager.cpp`

- [ ] **Step 1: 修改 net_test_manager.h，增加新接口**

在 `class net_test_manager` 的 `public:` 段，`vector<task::priority_task<test_case>> current_all_test();` 之后追加：

```cpp
    // 启动隧道健康检查定时器（30 秒一轮）
    void start_tunnel_health_check();

    // 对单个隧道做一次健康检查
    void check_tunnel_health(stream_tunnel *tunnel,
                             const std::function<void(bool, uint32_t)> &callback);
```

在 `private:` 段末尾追加：

```cpp
    static const uint32_t TUNNEL_HEALTH_CHECK_INTERVAL_MS = 30000;
    static const uint32_t TUNNEL_HEALTH_CHECK_TIMEOUT_MS = 5000;
    static const uint32_t TUNNEL_HEALTH_DOWN_THRESHOLD = 2;
    boost::asio::deadline_timer *health_check_timer = nullptr;
    void schedule_health_check();
    void run_health_check_round();
    static std::pair<std::string, uint16_t> parse_check_url(const std::string &url);
```

同时在文件顶部 includes 区追加（如还没有）：
```cpp
#include "stream_tunnel.h"
```

- [ ] **Step 2: 编译验证（仅头文件可能不报错）**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`（实现还没写但头文件不会破坏编译）

- [ ] **Step 3: 在 net_test_manager.cpp 末尾追加实现**

```cpp
std::pair<std::string, uint16_t> net_test_manager::parse_check_url(const std::string &url) {
    // 解析 https://host[:port][/path] 或 http://host[:port][/path]
    std::string s = url;
    uint16_t port = 443;
    if (s.find("https://") == 0) {
        s = s.substr(8);
        port = 443;
    } else if (s.find("http://") == 0) {
        s = s.substr(7);
        port = 80;
    }
    auto slash = s.find('/');
    if (slash != std::string::npos) {
        s = s.substr(0, slash);
    }
    auto colon = s.find(':');
    if (colon != std::string::npos) {
        port = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
        s = s.substr(0, colon);
    }
    return std::make_pair(s, port);
}

void net_test_manager::check_tunnel_health(stream_tunnel *tunnel,
                                           const std::function<void(bool, uint32_t)> &callback) {
    auto host_port = parse_check_url(tunnel->http_check_url);
    const std::string &host = host_port.first;
    uint16_t port = host_port.second;

    // 当前 net_test_manager 仅支持 443 TLS 探测
    if (port != 443) {
        logger::WARN << "tunnel" << tunnel->id() << "http_check_url port != 443, skip" << END;
        callback(false, 0);
        return;
    }

    // DNS 解析 host
    auto ips = st::utils::dns::query(st::proxy::config::uniq().dns, host);
    if (ips.empty()) {
        ips = st::utils::dns::query(host);
    }
    if (ips.empty()) {
        logger::WARN << "tunnel" << tunnel->id() << "resolve" << host << "failed" << END;
        callback(false, 0);
        return;
    }
    uint32_t target_ip = ips[0];

    auto net_callback = [=](bool valid, bool connected, uint32_t cost) {
        callback(valid, cost);
    };

    if (tunnel->type == "DIRECT") {
        tls_handshake(target_ip, net_callback);
    } else {
        tls_handshake_with_socks(tunnel->ip, tunnel->port,
                                 st::utils::ipv4::ip_to_str(target_ip), net_callback);
    }
}

void net_test_manager::run_health_check_round() {
    auto &tunnels = st::proxy::config::uniq().tunnels;
    for (auto *tunnel : tunnels) {
        check_tunnel_health(tunnel, [tunnel](bool valid, uint32_t cost) {
            tunnel->last_check_time.store(time::now());
            tunnel->last_check_cost.store(cost);
            if (valid) {
                tunnel->consecutive_failures.store(0);
                if (tunnel->health_status.load() != HEALTH_UP) {
                    logger::INFO << "tunnel" << tunnel->id() << "health UP cost" << cost << END;
                }
                tunnel->health_status.store(HEALTH_UP);
            } else {
                uint32_t failures = tunnel->consecutive_failures.fetch_add(1) + 1;
                if (failures >= TUNNEL_HEALTH_DOWN_THRESHOLD) {
                    if (tunnel->health_status.load() != HEALTH_DOWN) {
                        logger::WARN << "tunnel" << tunnel->id() << "health DOWN after"
                                     << failures << "consecutive failures" << END;
                    }
                    tunnel->health_status.store(HEALTH_DOWN);
                }
            }
        });
    }
}

void net_test_manager::schedule_health_check() {
    health_check_timer->expires_from_now(
            boost::posix_time::milliseconds(TUNNEL_HEALTH_CHECK_INTERVAL_MS));
    health_check_timer->async_wait([this](boost::system::error_code ec) {
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }
        run_health_check_round();
        schedule_health_check();
    });
}

void net_test_manager::start_tunnel_health_check() {
    if (health_check_timer != nullptr) {
        return;
    }
    health_check_timer = new boost::asio::deadline_timer(ic);
    // 立刻先做一轮，再进入定时
    ic.post([this]() {
        run_health_check_round();
        schedule_health_check();
    });
}
```

并在 `net_test_manager::~net_test_manager()` 中、`ic.stop()` 之前增加：
```cpp
    if (health_check_timer != nullptr) {
        boost::system::error_code ec;
        health_check_timer->cancel(ec);
    }
```

并在析构函数 `delete iw;` 之后增加：
```cpp
    delete health_check_timer;
    health_check_timer = nullptr;
```

- [ ] **Step 4: 编译验证**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`

- [ ] **Step 5: 提交**

```bash
git add src/core/analyzer/net_test_manager.h src/core/analyzer/net_test_manager.cpp
git commit -m "feat(net_test): 增加隧道主动健康检查能力"
```

---

## Task 4: 在 proxy_server 启动时启动健康检查

**Files:**
- Modify: `src/core/proxy_server.cpp`（在 server 启动后调用一次）

- [ ] **Step 1: 找到 proxy_server 启动入口**

执行 `grep -n "start\|console" src/core/proxy_server.cpp | head -20` 定位 `proxy_server::start()` 或类似入口。

- [ ] **Step 2: 在 server 启动入口、`session_manager`/`proxy_console` 启动逻辑附近追加调用**

```cpp
#include "analyzer/net_test_manager.h"
// ...
net_test_manager::uniq().start_tunnel_health_check();
```

放在配置加载和单例初始化完成之后即可（如果 proxy_server.cpp 没有合适入口，放在 `src/server/main.cpp` 启动 proxy_server 之后）。

- [ ] **Step 3: 编译验证**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`

- [ ] **Step 4: 提交**

```bash
git add -u
git commit -m "feat(proxy_server): 启动时启动隧道健康检查"
```

---

## Task 5: select_tunnels 中对 DOWN 隧道降权

**Files:**
- Modify: `src/core/analyzer/quality_analyzer.cpp`

- [ ] **Step 1: 找到 select_tunnels 打分循环**

文件 `src/core/analyzer/quality_analyzer.cpp:265-288`，循环体内现有打分逻辑。

- [ ] **Step 2: 在循环体内、`result.emplace_back(tunnel, ...)` 之前追加 DOWN 降权**

将 `result.emplace_back(tunnel, make_pair(score, ip_tunnel_record));` 之前插入：

```cpp
        // 主动健康检查标记 DOWN 的隧道大幅降权（不剔除，作为兜底）
        if (tunnel->is_down()) {
            score -= 100000;
        }
```

- [ ] **Step 3: 编译验证**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`

- [ ] **Step 4: 提交**

```bash
git add src/core/analyzer/quality_analyzer.cpp
git commit -m "feat(quality_analyzer): 健康检查 DOWN 隧道在 select_tunnels 中降权"
```

---

## Task 6: console 增加查看健康状态命令

**Files:**
- Modify: `src/core/console/proxy_console.cpp`

- [ ] **Step 1: 找到命令处理代码**

文件 `src/core/console/proxy_console.cpp`，`console->impl = ...` 内的 `if/else if` 链。

- [ ] **Step 2: 在最后一个 else if 之后、`return result;` 之前追加分支**

```cpp
        } else if (command == "proxy tunnel health") {
            string str;
            for (const auto &tunnel : st::proxy::config::uniq().tunnels) {
                int s = tunnel->health_status.load();
                const char *status_str =
                    (s == HEALTH_UP) ? "UP" : ((s == HEALTH_DOWN) ? "DOWN" : "UNKNOWN");
                uint64_t last = tunnel->last_check_time.load();
                str.append(tunnel->id())
                        .append("\t")
                        .append(tunnel->area)
                        .append("\t")
                        .append(status_str)
                        .append("\t")
                        .append(to_string(tunnel->consecutive_failures.load()))
                        .append("\t")
                        .append(to_string(tunnel->last_check_cost.load()))
                        .append("\t")
                        .append(last == 0 ? "-" : to_string(time::now() - last))
                        .append("\t")
                        .append(tunnel->http_check_url)
                        .append("\n");
            }
            strutils::trim(str);
            return make_pair(true, str);
        }
```

并在 `proxy_console.cpp` 顶部 includes 追加（如还没有）：
```cpp
#include "stream_tunnel.h"
```

- [ ] **Step 3: 编译验证**

Run: `cmake --build build --target st-proxy 2>&1 | tail -3`
Expected: `Built target st-proxy`

- [ ] **Step 4: 提交**

```bash
git add src/core/console/proxy_console.cpp
git commit -m "feat(console): 增加 proxy tunnel health 命令查看隧道健康状态"
```

---

## Task 7: 单元测试

**Files:**
- Create: `src/test/unit/tunnel_health_check_test.cpp`

- [ ] **Step 1: 写失败测试**

```cpp
//
// Created by codingdie on 2026-05-29.
//
#include "analyzer/net_test_manager.h"
#include "config.h"
#include "stream_tunnel.h"
#include <gtest/gtest.h>

TEST(proxy_unit_tests, test_parse_check_url) {
    // 通过友元或公共函数直接验证不便，改为通过 check_tunnel_health 行为间接测：
    // 这里仅验证 stream_tunnel 字段默认值与状态切换语义
    stream_tunnel t("DIRECT", "", 0);
    ASSERT_EQ(t.health_status.load(), HEALTH_UNKNOWN);
    ASSERT_FALSE(t.is_down());
    ASSERT_FALSE(t.is_up());

    t.health_status.store(HEALTH_UP);
    ASSERT_TRUE(t.is_up());
    ASSERT_FALSE(t.is_down());

    t.health_status.store(HEALTH_DOWN);
    ASSERT_TRUE(t.is_down());
    ASSERT_FALSE(t.is_up());
}

TEST(proxy_unit_tests, test_default_http_check_url_for_cn) {
    st::proxy::config::uniq().load("../confs/test");
    bool found_direct_or_cn = false;
    for (const auto *tunnel : st::proxy::config::uniq().tunnels) {
        if (tunnel->type == "DIRECT" || tunnel->area == "CN") {
            found_direct_or_cn = true;
            ASSERT_FALSE(tunnel->http_check_url.empty())
                    << "DIRECT/CN tunnel http_check_url should have default";
        } else {
            ASSERT_FALSE(tunnel->http_check_url.empty())
                    << "non-CN tunnel http_check_url should have default";
        }
    }
    ASSERT_TRUE(found_direct_or_cn);
}
```

- [ ] **Step 2: 在 CMakeLists.txt 中注册（如果使用 GLOB 自动收集，可跳过）**

执行 `grep -n "GLOB\|tunnel_health_check_test" /home/codingdie/codes/st-proxy/CMakeLists.txt | head -10` 确认。
如果使用了 `GLOB_RECURSE` 自动收集 `src/test/unit/*.cpp`，无需手动注册。
否则在测试可执行文件的源列表中追加 `src/test/unit/tunnel_health_check_test.cpp`。

- [ ] **Step 3: 重新生成构建系统并编译测试**

Run: `cmake -B build -DCMAKE_BUILD_TYPE=Debug -DOPENWRT=OFF && cmake --build build --target st-proxy-unit-test 2>&1 | tail -5`
Expected: `Built target st-proxy-unit-test`

- [ ] **Step 4: 运行测试**

Run: `cd build && ./st-proxy-unit-test --gtest_filter=proxy_unit_tests.test_parse_check_url:proxy_unit_tests.test_default_http_check_url_for_cn 2>&1 | tail -15`
Expected: 两个测试 PASSED

- [ ] **Step 5: 提交**

```bash
git add src/test/unit/tunnel_health_check_test.cpp
git commit -m "test: 添加隧道健康检查相关单元测试"
```

---

## Task 8: 全量测试 + 端到端验证

- [ ] **Step 1: 运行全部单元测试**

Run: `cd build && ctest --output-on-failure -j1 2>&1 | tail -20`
Expected: 除了原本就因网络问题失败的 `unit_tests.test_area_ip` 和 `UnitTests.test_logger`，其他全部通过

- [ ] **Step 2: 端到端启动验证**

```bash
./build/st-proxy -c ./confs/test &
PROXY_PID=$!
sleep 2

# 通过 UDP console 查询健康状态
echo "proxy tunnel health" | nc -u -w 2 127.0.0.1 5858

# 等待两轮检查
sleep 35
echo "proxy tunnel health" | nc -u -w 2 127.0.0.1 5858

kill $PROXY_PID
```
Expected: 第一次输出可能是 UNKNOWN 或刚开始检查；第二次输出至少有一个隧道是 UP 或 DOWN（取决于网络）

如果端到端验证因环境无法运行，跳过本步骤但在 commit message 中说明。

- [ ] **Step 3: 提交（如果 README 需要更新）**

```bash
# 如果有文档更新
git add -u
git commit -m "docs: 更新 README 增加 tunnel health 命令说明"
```

---

## OpenWrt 包同步提醒

按 CLAUDE.md 要求，本项目作为 OpenWrt package 提供，需要同步更新插件代码：
- 路径：`../home-openwrt/codingdie-packages/packages/st-proxy`
- 检查项：是否需要更新版本号、Makefile、配置文件示例

**这部分由执行计划的人在所有任务完成后处理一次，不在主任务中。**

---

## 设计自检要点

- 默认 http_check_url 行为：CN/DIRECT → baidu，其他 → google ✓
- 隧道 DOWN 后不剔除而是大幅降权 ✓（保证全部 DOWN 时仍有兜底）
- 探测周期 30s，连续 2 次失败标记 DOWN，1 次成功立即恢复 UP ✓
- 健康状态全部用 std::atomic，避免锁 ✓
- 现有 IP 维度探测保持不变 ✓
