# Common Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `st-proxy/src/common` and `st-dns/src/common` fully identical while preserving the verified runtime fixes and keeping both repositories buildable.

**Architecture:** First identify one canonical content set for the eight divergent files, preferring the safer `st-dns` shutdown/logger patterns plus the verified `st-proxy` fallback fixes where needed. Then apply those exact file contents to both repositories, verify the `src/common` tree is byte-identical, and run focused tests in each repo to confirm the shared module still works.

**Tech Stack:** C++17, CMake, GoogleTest, Boost.Asio, Boost.Log, LevelDB.

---

### Task 1: Reconfirm the exact divergence set

**Files:**
- Modify: `docs/superpowers/plans/2026-05-30-common-sync-plan.md`
- Check: `/home/codingdie/codes/st-proxy/src/common`
- Check: `/home/codingdie/codes/st-dns/src/common`

- [ ] **Step 1: Diff the two `src/common` trees and save the exact file list**

Run:
```bash
python3 - <<'PY'
from pathlib import Path
p1=Path('/home/codingdie/codes/st-proxy/src/common')
p2=Path('/home/codingdie/codes/st-dns/src/common')
files=sorted(str(p.relative_to(p1)) for p in p1.rglob('*') if p.is_file())
diffs=[]
for rel in files:
    a=(p1/rel).read_text(errors='ignore').splitlines()
    b=(p2/rel).read_text(errors='ignore').splitlines()
    if a!=b:
        diffs.append(rel)
print('\n'.join(diffs))
print(f'TOTAL_DIFFS={len(diffs)}')
PY
```
Expected: exactly these 8 paths differ:
```text
main/command/proxy_command.h
main/kv/disk_kv.cpp
main/taskquque/task_queue.h
main/utils/area_ip.cpp
main/utils/file.h
main/utils/logger.cpp
main/utils/logger.h
test/unit_tests.cpp
```

- [ ] **Step 2: Verify both trees contain the same file inventory**

Run:
```bash
diff <(cd /home/codingdie/codes/st-proxy && find src/common -type f | sort) \
     <(cd /home/codingdie/codes/st-dns && find src/common -type f | sort)
```
Expected: no output.

- [ ] **Step 3: Commit the planning baseline if needed**

```bash
git add docs/superpowers/specs/2026-05-30-common-sync-design.md \
        docs/superpowers/plans/2026-05-30-common-sync-plan.md
git commit -m "docs: add common sync design and plan"
```

### Task 2: Define the canonical `file.h` behavior

**Files:**
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/utils/file.h`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/utils/file.h`
- Test: `/home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp`
- Test: `/home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp`

- [ ] **Step 1: Confirm the failing behavior by inspection**

Read the current `mkdirs()` implementation and verify the missing success return in at least one repo:
```bash
sed -n '37,55p' /home/codingdie/codes/st-proxy/src/common/main/utils/file.h
sed -n '37,55p' /home/codingdie/codes/st-dns/src/common/main/utils/file.h
```
Expected: success path lacks `return true;` in the outdated copy.

- [ ] **Step 2: Set the canonical implementation**

Use this exact body in both repos:
```cpp
inline bool mkdirs(const string &path) {
    boost::system::error_code error;
    boost::filesystem::path bpath(path);
    if (boost::filesystem::exists(bpath) && boost::filesystem::is_directory(path)) {
        return true;
    }
    boost::filesystem::create_directories(bpath, error);
    if (error) {
        std::cerr << error << std::endl;
        return false;
    }
    return true;
}
```

- [ ] **Step 3: Verify the files are identical**

Run:
```bash
diff /home/codingdie/codes/st-proxy/src/common/main/utils/file.h \
     /home/codingdie/codes/st-dns/src/common/main/utils/file.h
```
Expected: no output.

- [ ] **Step 4: Commit the shared fix**

```bash
git -C /home/codingdie/codes/st-proxy add src/common/main/utils/file.h
git -C /home/codingdie/codes/st-proxy commit -m "fix(common): return success from mkdirs"

git -C /home/codingdie/codes/st-dns add src/common/main/utils/file.h
git -C /home/codingdie/codes/st-dns commit -m "fix(common): return success from mkdirs"
```

### Task 3: Define the canonical logger/APM shutdown implementation

**Files:**
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/utils/logger.h`
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/utils/logger.cpp`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/utils/logger.h`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/utils/logger.cpp`
- Test: `/home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp`
- Test: `/home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp`

- [ ] **Step 1: Use `st-dns` logger as the canonical base**

The canonical behavior must include all of these:
```cpp
static void report_apm_log_local(bool report_status_log = true);
```
```cpp
IO_CONTEXT.restart();
```
```cpp
LOG_THREADS.clear();
```
```cpp
if (ec == boost::asio::error::operation_aborted) {
    return;
}
```
```cpp
void logger::disable() {
    apm_logger::disable();
    boost::shared_ptr<logging::core> core = logging::core::get();
    core->flush();
    core->remove_all_sinks();
    core->reset_filter();
}
```
And `apm_logger::disable(false)` must suppress status logging during teardown flush.

- [ ] **Step 2: Mirror the same `logger.h` and `logger.cpp` into both repos**

Run:
```bash
cp /home/codingdie/codes/st-dns/src/common/main/utils/logger.h \
   /home/codingdie/codes/st-proxy/src/common/main/utils/logger.h
cp /home/codingdie/codes/st-dns/src/common/main/utils/logger.cpp \
   /home/codingdie/codes/st-proxy/src/common/main/utils/logger.cpp
```
Then, if needed, copy the exact same final files back from the chosen canonical workspace into `st-dns` too, so both are byte-identical.

- [ ] **Step 3: Verify the logger files are identical**

Run:
```bash
diff /home/codingdie/codes/st-proxy/src/common/main/utils/logger.h \
     /home/codingdie/codes/st-dns/src/common/main/utils/logger.h

diff /home/codingdie/codes/st-proxy/src/common/main/utils/logger.cpp \
     /home/codingdie/codes/st-dns/src/common/main/utils/logger.cpp
```
Expected: no output.

- [ ] **Step 4: Commit the logger sync**

```bash
git -C /home/codingdie/codes/st-proxy add src/common/main/utils/logger.h src/common/main/utils/logger.cpp
git -C /home/codingdie/codes/st-proxy commit -m "fix(common): unify logger shutdown behavior"

git -C /home/codingdie/codes/st-dns add src/common/main/utils/logger.h src/common/main/utils/logger.cpp
git -C /home/codingdie/codes/st-dns commit -m "fix(common): unify logger shutdown behavior"
```

### Task 4: Define the canonical writable KV fallback behavior

**Files:**
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/kv/disk_kv.cpp`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/kv/disk_kv.cpp`
- Test: `/home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp`
- Test: `/home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp`

- [ ] **Step 1: Standardize on one writable-folder selection strategy**

The canonical implementation must:
- try `ST_KV_FOLDER` first when set
- then try `/var/lib/st/kv/`
- then fall back to `/tmp/st/kv/`
- `assert(status.ok())` only after all candidates fail

Canonical helper shape:
```cpp
static vector<string> kv_folders() {
    vector<string> folders;
    const char *env_folder = std::getenv("ST_KV_FOLDER");
    if (env_folder != nullptr && env_folder[0] != '\0') {
        folders.emplace_back(normalize_kv_folder(env_folder));
    }
    folders.emplace_back("/var/lib/st/kv/");
    folders.emplace_back("/tmp/st/kv/");
    return folders;
}
```

- [ ] **Step 2: Standardize `clear()` on the safer delete-after-collect pattern**

Canonical `clear()` body:
```cpp
void disk_kv::clear() {
    std::vector<std::string> keys;
    leveldb::Iterator *it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        keys.push_back(it->key().ToString());
    }
    delete it;

    for (const auto &key : keys) {
        erase(key);
    }
}
```

- [ ] **Step 3: Mirror the exact final `disk_kv.cpp` into both repos**

Run:
```bash
diff /home/codingdie/codes/st-proxy/src/common/main/kv/disk_kv.cpp \
     /home/codingdie/codes/st-dns/src/common/main/kv/disk_kv.cpp
```
Expected after sync: no output.

- [ ] **Step 4: Commit the KV sync**

```bash
git -C /home/codingdie/codes/st-proxy add src/common/main/kv/disk_kv.cpp
git -C /home/codingdie/codes/st-proxy commit -m "fix(common): unify writable disk kv fallback"

git -C /home/codingdie/codes/st-dns add src/common/main/kv/disk_kv.cpp
git -C /home/codingdie/codes/st-dns commit -m "fix(common): unify writable disk kv fallback"
```

### Task 5: Unify the common tests

**Files:**
- Modify: `/home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp`
- Modify: `/home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp`

- [ ] **Step 1: Use the richer `st-dns` test set as the canonical base**

The canonical test file must include:
- `test_logger` with `logger::disable()` before file-count assertions
- `apm_logger_disable_can_skip_status_log`
- `logger_disable_keeps_apm_status_log`
- `test_disk_kv_expire`

- [ ] **Step 2: Mirror the same `unit_tests.cpp` into both repos**

Run:
```bash
cp /home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp \
   /home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp
```
Then verify the same content exists in both repos.

- [ ] **Step 3: Verify the test files are identical**

Run:
```bash
diff /home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp \
     /home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp
```
Expected: no output.

- [ ] **Step 4: Commit the common test sync**

```bash
git -C /home/codingdie/codes/st-proxy add src/common/test/unit_tests.cpp
git -C /home/codingdie/codes/st-proxy commit -m "test(common): unify common module regression tests"

git -C /home/codingdie/codes/st-dns add src/common/test/unit_tests.cpp
git -C /home/codingdie/codes/st-dns commit -m "test(common): unify common module regression tests"
```

### Task 6: Resolve the remaining business-common divergences

**Files:**
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/command/proxy_command.h`
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/taskquque/task_queue.h`
- Modify: `/home/codingdie/codes/st-proxy/src/common/main/utils/area_ip.cpp`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/command/proxy_command.h`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/taskquque/task_queue.h`
- Modify: `/home/codingdie/codes/st-dns/src/common/main/utils/area_ip.cpp`

- [ ] **Step 1: Diff each remaining file and record semantic differences**

Run:
```bash
for f in \
  main/command/proxy_command.h \
  main/taskquque/task_queue.h \
  main/utils/area_ip.cpp
 do
  echo "=== $f ==="
  diff -u /home/codingdie/codes/st-proxy/src/common/$f \
          /home/codingdie/codes/st-dns/src/common/$f || true
 done
```
Expected: concrete diffs only in these three files.

- [ ] **Step 2: Choose one exact final version for each file**

Rules:
- If the change is bugfix-only and obviously safer, keep that version.
- If each repo has a necessary behavior, merge it once in one file.
- After merging, copy the exact final file into the other repo.

- [ ] **Step 3: Verify these files are identical**

Run:
```bash
for f in \
  main/command/proxy_command.h \
  main/taskquque/task_queue.h \
  main/utils/area_ip.cpp
 do
  diff /home/codingdie/codes/st-proxy/src/common/$f \
       /home/codingdie/codes/st-dns/src/common/$f
 done
```
Expected: no output.

- [ ] **Step 4: Commit the remaining common sync**

```bash
git -C /home/codingdie/codes/st-proxy add \
  src/common/main/command/proxy_command.h \
  src/common/main/taskquque/task_queue.h \
  src/common/main/utils/area_ip.cpp
git -C /home/codingdie/codes/st-proxy commit -m "refactor(common): unify remaining shared module files"

git -C /home/codingdie/codes/st-dns add \
  src/common/main/command/proxy_command.h \
  src/common/main/taskquque/task_queue.h \
  src/common/main/utils/area_ip.cpp
git -C /home/codingdie/codes/st-dns commit -m "refactor(common): unify remaining shared module files"
```

### Task 7: Prove both `src/common` trees are byte-identical

**Files:**
- Check: `/home/codingdie/codes/st-proxy/src/common`
- Check: `/home/codingdie/codes/st-dns/src/common`

- [ ] **Step 1: Run a recursive diff across the full trees**

Run:
```bash
diff -ruN /home/codingdie/codes/st-proxy/src/common \
          /home/codingdie/codes/st-dns/src/common
```
Expected: no output.

- [ ] **Step 2: Generate matching hashes for both trees**

Run:
```bash
python3 - <<'PY'
from pathlib import Path
import hashlib
for root in ['/home/codingdie/codes/st-proxy/src/common', '/home/codingdie/codes/st-dns/src/common']:
    h=hashlib.sha256()
    for p in sorted(Path(root).rglob('*')):
        if p.is_file():
            h.update(str(p.relative_to(root)).encode())
            h.update(p.read_bytes())
    print(root, h.hexdigest())
PY
```
Expected: the two SHA256 values are identical.

### Task 8: Rebuild and run focused verification in `st-proxy`

**Files:**
- Test: `/home/codingdie/codes/st-proxy/src/common/test/unit_tests.cpp`
- Test: `/home/codingdie/codes/st-proxy/src/test/unit/tunnel_health_check_test.cpp`

- [ ] **Step 1: Rebuild the relevant test binaries**

Run:
```bash
cd /home/codingdie/codes/st-proxy
cmake --build build --target st-unit-test st-proxy-unit-test
```
Expected: build exit code 0.

- [ ] **Step 2: Run the common regression tests**

Run:
```bash
cd /home/codingdie/codes/st-proxy/build
./st-unit-test --gtest_filter=unit_tests.test_disk_kv
./st-unit-test --gtest_filter=UnitTests.test_logger
```
Expected: both pass and exit 0.

- [ ] **Step 3: Run the proxy health-check regressions**

Run:
```bash
cd /home/codingdie/codes/st-proxy/build
./st-proxy-unit-test --gtest_filter=proxy_unit_tests.test_tunnel_health_status_transitions
./st-proxy-unit-test --gtest_filter=proxy_unit_tests.test_default_http_check_url_for_cn
./st-proxy-unit-test --gtest_filter=proxy_unit_tests.test_quality_analyzer
```
Expected: each test reports `[  PASSED  ]` and exits 0 in the current sandbox.

### Task 9: Rebuild and run focused verification in `st-dns`

**Files:**
- Test: `/home/codingdie/codes/st-dns/src/common/test/unit_tests.cpp`

- [ ] **Step 1: Rebuild the unit test binary**

Run:
```bash
cd /home/codingdie/codes/st-dns
cmake --build build --target st-unit-test
```
Expected: build exit code 0.

- [ ] **Step 2: Run the common regression tests**

Run:
```bash
cd /home/codingdie/codes/st-dns/build
./st-unit-test --gtest_filter=unit_tests.test_disk_kv
./st-unit-test --gtest_filter=unit_tests.test_disk_kv_expire
./st-unit-test --gtest_filter=unit_tests.test_logger
```
Expected: all three pass and exit 0.

### Task 10: Final cleanliness check

**Files:**
- Check: `/home/codingdie/codes/st-proxy`
- Check: `/home/codingdie/codes/st-dns`

- [ ] **Step 1: Check git status in both repos**

Run:
```bash
git -C /home/codingdie/codes/st-proxy status --short

git -C /home/codingdie/codes/st-dns status --short
```
Expected: only the intended tracked changes remain, with no surprise edits.

- [ ] **Step 2: Capture the final diff summary for both repos**

Run:
```bash
git -C /home/codingdie/codes/st-proxy diff --stat

git -C /home/codingdie/codes/st-dns diff --stat
```
Expected: the stats only reflect the synchronized `src/common` files and plan/spec docs.
