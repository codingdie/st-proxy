# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 额外说明
这个项目作为openwrt package提供出去，需要同时修改插件代码，插件代码在../home-openwrt/codingdie-packages/packages/st-proxy下，你需要阅读和修改此代码

### 项目记忆
- 线上运行机器：`192.168.31.1`
- 线上日志目录：`/tmp/st`
- 排查线上问题时，优先到 `192.168.31.1:/tmp/st` 拉取或查看日志
- 当在非 `develop`、`main` 分支开发时（通常是使用 `worktree` 开发），只在当前 `worktree` 分支做本地 `commit`，不要 `push`；随后将 `develop` 分支 `rebase` 到当前 `worktree` 分支包含的提交上，再从 `develop` 执行 `push`

## Project Overview

st-proxy is a smart local transport proxy written in C++ that supports multiple SOCKS5/direct stream tunnel chains. It automatically intercepts local TCP sessions and intelligently selects the best tunnel based on destination area and quality metrics.

## Build System

This project uses CMake with C++11 standard.

```bash
# Development build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Release build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Install (default: /usr/local)
./install.sh

# Install to custom prefix
./install.sh /custom/path
```

### Protobuf Code Generation

The project uses protobuf for serialization:
- `src/core/proto/message.proto` → `message.pb.{h,cc}`
- `src/common/main/proto/kv.proto` → `kv.pb.{h,cc}`

**Important**: Generated files are placed in the source tree. Protobuf targets:
```bash
make st-proxy-proto
make st-common-proto
```

**Note**: Tests are disabled in OpenWrt builds (OPENWRT=ON)

### Running Tests

```bash
# Build and run all tests (tests only build when OPENWRT=OFF). Unit tests run
# in parallel; integration tests begin only after every unit test has finished.
cd build
ctest --output-on-failure -j8

# 外部链路冒烟测试（访问公网及配置的 SOCKS 服务，不属于默认测试）
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DST_PROXY_ENABLE_EXTERNAL_TESTS=ON
cmake --build build
cd build
sudo -n ctest --output-on-failure -j1 -L external

# Run specific test executables
./st-unit-test           # Common utilities tests
./st-proxy-unit-test     # Proxy core unit tests
./st-proxy-integration-test # Integration tests

# Run specific test with gtest filter
./st-proxy-unit-test --gtest_filter=proxy_unit_tests.test_quality_analyzer

# Note: Tests are disabled in OpenWrt builds
```

**Important**: Integration tests must be run as root. The integration test installs iptables/ipset NAT rules and
st-proxy uses `SO_MARK` to prevent its own outbound connections from being redirected back into the proxy.

```bash
# Direct run (searches default config paths)
st-proxy

# Specify config directory
st-proxy -c /path/to/config

# Run as daemon
sudo st-proxy -d start
sudo st-proxy -d stop
sudo st-proxy -d restart
```

## Architecture

### Core Components

**proxy_server** (`src/core/proxy_server.{h,cpp}`)
- Main server class that manages the entire proxy lifecycle
- Uses Boost.Asio for async I/O with configurable thread pool
- Handles NAT traffic interception on Linux (iptables) and macOS (pf)
- Manages TCP acceptor and distributes connections across worker contexts

**session_manager** (`src/core/session_manager.{h,cpp}`)
- Manages all active proxy sessions
- Tracks connections in an unordered_map by session ID
- Provides port allocation for sessions
- Runs periodic monitoring to clean up dead sessions

**proxy_session** (`src/core/proxy_session.{h,cpp}`)
- Represents a single TCP proxy connection
- State machine: CONNECTING → CONNECTED → DESTROYING → DESTROYED
- Handles bidirectional data transfer between client and proxy/direct sockets
- Implements tunnel selection logic based on destination area and whitelist
- Manages SOCKS5 protocol handshake for proxy tunnels

**stream_tunnel** (`src/core/stream_tunnel.{h,cpp}`)
- Represents a tunnel configuration (DIRECT or SOCKS)
- Contains area information, whitelist domains/IPs
- Used by sessions to determine routing

**quality_analyzer** (`src/core/quality_analyzer.{h,cpp}`)
- Tracks tunnel quality metrics per destination IP
- Records first packet latency and failure rates
- Uses protobuf for persistent storage via LevelDB
- Helps select optimal tunnel for each connection

**config** (`src/core/config.{h,cpp}`)
- Singleton that loads JSON configuration from standard paths
- Parses tunnel definitions, whitelist, DNS settings
- Resolves domain whitelists to IP addresses

**nat_utils** (`src/core/nat_utils.{h,cpp}`)
- Platform-specific NAT handling (Linux iptables, macOS pf)
- Retrieves original destination address for intercepted connections
- Manages whitelist for bypassing proxy

### Proxy Flow

1. Client initiates TCP connection → intercepted by NAT rules → redirected to st-proxy
2. proxy_server accepts connection and creates proxy_session
3. proxy_session retrieves original destination via nat_utils
4. Session selects appropriate tunnel based on destination area/whitelist
5. Connects to destination via selected tunnel (DIRECT or SOCKS5)
6. Bidirectional data transfer between client and destination
7. quality_analyzer records connection metrics for future optimization

### Tunnel Selection Logic

The `proxy_session::select_tunnels()` method chooses tunnels based on:
- Domain/IP whitelist matching (global and per-tunnel)
- Geographic area restrictions (CN, US, JP, etc.)
- Historical quality metrics from quality_analyzer
- Tunnel order in configuration

### Directory Structure

```
src/
├── core/              # Proxy server core logic
│   ├── proto/         # Protobuf definitions (message.proto)
│   ├── proxy_server.* # Main server
│   ├── session_manager.* # Session lifecycle
│   ├── proxy_session.* # Individual connection
│   ├── stream_tunnel.* # Tunnel configuration
│   ├── quality_analyzer.* # Quality tracking
│   ├── config.*       # Configuration loading
│   └── nat_utils.*    # NAT interception
├── common/main/       # Shared utilities
│   ├── kv/           # Key-value storage (LevelDB wrapper)
│   ├── proto/        # Protobuf definitions (kv.proto)
│   ├── utils/        # File, network, string utilities
│   ├── console/      # UDP console for management
│   ├── command/      # Command execution
│   └── thirdpart/    # Third-party headers (httplib.h)
├── server/           # Entry point (main.cpp)
└── test/             # Tests
    ├── unit/         # Unit tests
    └── integration/  # Integration tests
```

## Configuration

Configuration is JSON-based. See `confs/config.json` for reference.

Key configuration elements:
- `ip`/`port`: Local bind address (default: 0.0.0.0:40000)
- `tunnels`: Array of tunnel configs with type (DIRECT/SOCKS), area, whitelist
- `so_timeout`: Socket timeout in milliseconds
- `connect_timeout`: Connection timeout in milliseconds
- `parallel`: Number of I/O worker threads
- `dns`: Preferred DNS server (recommend st-dns)
- `whitelist`: Global domains/IPs to bypass proxy

Configuration search paths (in order):
1. Path specified via `-c` flag
2. `../confs` (relative to binary)
3. `/usr/local/etc/st/proxy`
4. `/etc/st/proxy`

Platform-specific configs in `confs/`:
- `linux/`: Linux iptables NAT rules and systemd service
- `darwin/`: macOS pf rules
- `openwrt/`: OpenWRT integration

## Dependencies

Required libraries (see README.md for versions):
- CMake >= 3.11
- Boost >= 1.7.0 (system, filesystem, thread, program_options)
- OpenSSL >= 1.0.2
- Protocol Buffers (libprotobuf-lite)
- LevelDB

## OpenWrt Build

This project is designed to build for OpenWrt. The CMakeLists.txt includes special handling when `OPENWRT=ON`:
- Skips Google Test dependencies
- Installs OpenWrt-specific configs from `confs/openwrt/`
- Uses OpenWrt toolchain and staging directories

The project is packaged in the codingdie-packages feed for OpenWrt.

### 软件包版本

- 修改 OpenWrt 插件代码时，不要自动修改 `PKG_VERSION` 或 `PKG_RELEASE`。
- 只有用户明确要求升级、调整或发布软件包版本时，才能修改这两个字段。

## Key Implementation Details

### Protobuf Usage
- `message.proto`: Quality metrics serialization for LevelDB storage
- `kv.proto`: Value wrapper with expiration for persistent cache

### NAT Interception
- **Linux**: Uses iptables REDIRECT rules (see `confs/linux/nat/rule.sh`)
- **macOS**: Uses pf (packet filter) with DIOCNATLOOK ioctl
- Original destination retrieved before proxying

### Quality Tracking
- Per-IP, per-tunnel metrics stored in LevelDB
- Tracks first packet latency and success/failure rates
- Used to optimize tunnel selection for future connections

### Logging
- Custom logging via `st.h` logger macros
- Optional UDP log servers for raw logs and APM metrics
- Log levels: DEBUG/INFO/WARN/ERROR

### Thread Model
- Main thread: TCP acceptor loop
- Worker threads: Configurable pool for I/O operations (default: 8)
- Each worker has its own io_context for async operations
- session_manager runs periodic cleanup timer

### Common Utilities (src/common/main/)
- **kv/**: Key-value storage abstraction with LevelDB backend
- **utils/**: File operations, IPv4 utilities, DNS resolution, area-IP mapping
- **console/**: UDP console for runtime management
- **command/**: Command processing framework

### Build System Notes
- Uses `file(GLOB_RECURSE)` to collect source files automatically
- Protobuf files must be generated before building
- Third-party header `httplib.h` is auto-downloaded during CMake configuration if missing

## Claude 工作习惯

### 语言偏好

默认使用中文进行交流和编写代码注释。

### Git 配置与规范
**重要：所有 Git 操作必须遵循以下规范**

- 用户名：codingdie
- 邮箱：codingdie@gmail.com
- 所有提交必须使用此身份
- **不要在 commit message 中添加 Co-Authored-By 标签**
- 修改代码后**不要自动 commit**
- 等待用户明确说"提交"、"commit"或"push"后，再执行 `git commit` + `git push`
- 可以使用 `git diff` 或 `git status` 查看改动，但不要自动提交
