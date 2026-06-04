# st-proxy Common Sync From st-dns Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `st-proxy/src/common` with `st-dns/src/common` and adapt only non-`common` `st-proxy` code until the project builds and test results are known.

**Architecture:** Treat `st-dns/src/common` as the canonical shared module. Copy it into `st-proxy/src/common`, then make all compatibility changes in `src/core`, `src/test`, `CMakeLists.txt`, or packaging/config files outside `src/common`.

**Tech Stack:** C++11, CMake, GoogleTest, Boost.Asio, Boost.Log, LevelDB, Protobuf.

---

### Task 1: Snapshot and Sync Common

**Files:**
- Replace: `/home/codingdie/codes/st-proxy/src/common`
- Source: `/home/codingdie/codes/st-dns/src/common`

- [ ] **Step 1: Record the current divergent common files**

Run:
```bash
git diff --no-index --stat /home/codingdie/codes/st-dns/src/common /home/codingdie/codes/st-proxy/src/common
```

Expected: the command exits `1` because differences exist and prints the common file diff summary.

- [ ] **Step 2: Copy st-dns common over st-proxy common**

Run:
```bash
rsync -a --delete /home/codingdie/codes/st-dns/src/common/ /home/codingdie/codes/st-proxy/src/common/
```

Expected: no output on success.

- [ ] **Step 3: Verify common trees are identical**

Run:
```bash
git diff --no-index /home/codingdie/codes/st-dns/src/common /home/codingdie/codes/st-proxy/src/common
```

Expected: exit `0` and no output.

### Task 2: Build and Collect Adaptation Errors

**Files:**
- Read: `/home/codingdie/codes/st-proxy/CMakeLists.txt`
- Read: `/home/codingdie/codes/st-proxy/src/core/**`
- Read: `/home/codingdie/codes/st-proxy/src/test/**`

- [ ] **Step 1: Build the project**

Run:
```bash
cmake --build build
```

Expected: either build succeeds, or compiler/linker errors identify non-`common` callers that need adaptation.

- [ ] **Step 2: Search for removed or changed common lifecycle APIs**

Run:
```bash
rg -n "areaip::manager::uniq\\(\\)\\.(start|stop|started)|apm_logger::ensure_inited|udp_console::stop|console->stop|schedule_log\\(" src/core src/test CMakeLists.txt -g '!src/common/**'
```

Expected: no matches, or matches only in non-`common` files that must be edited.

### Task 3: Adapt Non-common Callers

**Files:**
- Modify as needed: `/home/codingdie/codes/st-proxy/src/core/**/*.cpp`
- Modify as needed: `/home/codingdie/codes/st-proxy/src/core/**/*.h`
- Modify as needed: `/home/codingdie/codes/st-proxy/src/test/**/*.cpp`
- Modify as needed: `/home/codingdie/codes/st-proxy/CMakeLists.txt`
- Do not modify: `/home/codingdie/codes/st-proxy/src/common/**`

- [ ] **Step 1: Fix compile errors outside common**

For each compiler error, identify whether it references a removed or changed common interface. Edit only the caller file outside `src/common`.

Allowed edit examples:
```cpp
// If a caller used a removed explicit lifecycle call:
// st::areaip::manager::uniq().start();
// Remove it, because st-dns common starts manager runtime in the constructor.
```

```cpp
// If a caller used a removed udp_console stop method:
// console->stop();
// Replace the owner shutdown path with delete/reset ownership only.
delete console;
console = nullptr;
```

Expected: no edits under `src/common`.

- [ ] **Step 2: Rebuild after each adaptation batch**

Run:
```bash
cmake --build build
```

Expected: compiler error count decreases. Continue until build succeeds or a blocking incompatibility is identified.

- [ ] **Step 3: Confirm common stayed untouched after sync**

Run:
```bash
git diff --no-index /home/codingdie/codes/st-dns/src/common /home/codingdie/codes/st-proxy/src/common
```

Expected: exit `0` and no output.

### Task 4: Verify Tests and Report Remaining Environment Limits

**Files:**
- Read: `/home/codingdie/codes/st-proxy/build/Testing/Temporary/LastTest.log`
- Read: `/home/codingdie/codes/st-proxy/src/test/**`

- [ ] **Step 1: Run focused build-level verification**

Run:
```bash
cmake --build build
```

Expected: build succeeds.

- [ ] **Step 2: Run common/unit discovery**

Run:
```bash
ctest -N
```

Expected: tests are discovered.

- [ ] **Step 3: Run full test command with serial execution**

Run:
```bash
ctest --output-on-failure -j1 --timeout 30
```

Expected: tests that do not depend on external network or currently hanging static destructors pass. Any timeout/failure is recorded with test name and reason.

- [ ] **Step 4: Report verification outcome**

Report these items:

1. Whether `src/common` is byte-identical to `st-dns/src/common`.
2. Which non-`common` files were changed for adaptation.
3. Build command result.
4. Test command result, including known timeout/environment limitations.

### Task 5: Check OpenWrt Package Impact

**Files:**
- Read: `/home/codingdie/codes/home-openwrt/codingdie-packages/packages/st-proxy/Makefile`
- Read: `/home/codingdie/codes/home-openwrt/codingdie-packages/packages/st-proxy/files/config.json`

- [ ] **Step 1: Inspect package references**

Run:
```bash
sed -n '1,220p' /home/codingdie/codes/home-openwrt/codingdie-packages/packages/st-proxy/Makefile
```

Expected: package builds from the `st-proxy` source and passes `-DOPENWRT=ON`.

- [ ] **Step 2: Decide whether package files need edits**

If the adaptation only touches tests or non-installed runtime internals, no package edit is required. If config keys or installed file paths change, edit only the package file that references those keys/paths.

Expected: record the decision in the final response.
