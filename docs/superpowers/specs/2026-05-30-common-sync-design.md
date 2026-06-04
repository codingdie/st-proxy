# Common Sync Design

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `st-proxy/src/common` and `st-dns/src/common` byte-for-byte identical, while preserving required runtime fixes and keeping both projects buildable.

**Architecture:** Use a single chosen `common` source set as the canonical content, then apply the same file contents to both repositories. For files that currently diverge in behavior (`disk_kv`, `logger`, `file`, `area_ip`, `task_queue`, `proxy_command`, tests), resolve differences once in the chosen canonical version and mirror that exact result into both repos. Keep non-`common` project code untouched.

**Tech Stack:** C++17, CMake, GoogleTest, LevelDB, Boost.Asio, Boost.Log.

---

## Scope

- Synchronize every file under `src/common` between `st-proxy` and `st-dns`.
- Preserve the shared bug fixes already verified:
  - `file::mkdirs()` must return `true` on success.
  - `disk_kv` must fall back to a writable KV directory when `/var/lib/st/kv/` is unavailable.
  - logger/APM shutdown must not crash during process teardown.
- Do not touch non-`common` code unless a build error forces a header/API adjustment.

## File Set

The current content diffs are limited to:
- `src/common/main/command/proxy_command.h`
- `src/common/main/kv/disk_kv.cpp`
- `src/common/main/taskquque/task_queue.h`
- `src/common/main/utils/area_ip.cpp`
- `src/common/main/utils/file.h`
- `src/common/main/utils/logger.cpp`
- `src/common/main/utils/logger.h`
- `src/common/test/unit_tests.cpp`

## Canonicalization Rule

- Prefer the `st-dns` version when it already contains the safer shutdown / test behavior.
- Keep the `file::mkdirs()` return-value fix in both repos.
- For the remaining behavioral files, resolve the differences in one canonical copy first, then copy the exact same content into the other repo.

## Success Criteria

- `diff -ruN /home/codingdie/codes/st-proxy/src/common /home/codingdie/codes/st-dns/src/common` returns no differences.
- Both repositories still build their unit test targets.
- The key common tests pass in each repo:
  - `test_disk_kv`
  - `test_disk_kv_expire`
  - `test_logger`
  - the proxy health-check tests already added in `st-proxy`
