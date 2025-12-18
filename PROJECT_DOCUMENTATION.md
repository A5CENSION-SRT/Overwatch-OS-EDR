## Chapter 1 — Introduction

Project Overwatch is a userspace Endpoint Detection and Response (EDR) prototype for Linux x86_64 that leverages the `ptrace` debugging API to monitor and optionally enforce policy on system calls made by a traced program. It is intentionally instructional: the codebase is small, readable, and split into clear phases that mirror typical EDR concerns (instrumentation, decoding, inspection, enforcement). The emphasis is on transparency of technique rather than production-grade completeness.

Core objectives and learning outcomes:
- Observe and log every system call a target process makes from birth to exit, capturing both entry and exit semantics (double-stop model).
- Decode syscall purpose (file, network, process, system) and reconstruct arguments such as file paths or socket addresses via safe cross-process memory reads.
- Evaluate heuristic rules that flag or terminate suspicious activity and emit operator telemetry (colored syscall stream, alerts, final statistics).
- Demonstrate how ptrace-based monitoring can be composed without kernel modules while highlighting real-world gaps and evasion points.

Threat and scope model:
- **In scope (what it covers):** Per-process syscall tracing; immediate exec boundary; path- and port-based heuristics for file, process, and network behaviors; sample “malicious” workloads for demonstration.
- **Out of scope / current gaps:** No descendant (fork/clone/vfork) tracing; no true syscall blocking (RAX not mutated); no kernel hardening or seccomp; limited rule expressiveness; assumes 64-bit Linux; not resilient against ptrace-aware malware.

Intended audience: security learners, reverse-engineering students, and developers exploring ptrace, syscall observability, and simple heuristic enforcement pipelines.


## Chapter 2 — Implementation

### Architecture Overview
Overwatch is organized into four phases, each with a dedicated module:
1) **Process instrumentation (`src/tracer.c`)** — fork/exec tracing setup, `ptrace` option configuration, interception loop, double-stop tracking, and signal relay.
2) **Syscall decoding (`src/decoder.c`)** — syscall naming, category classification (FILE/NETWORK/PROCESS/SYSTEM), and colored operator output on syscall entry.
3) **Memory inspection (`src/memory.c`)** — safe extraction of strings/bytes from the tracee via `PTRACE_PEEKDATA`, enabling rule checks on file paths and socket addresses.
4) **Heuristic enforcement (`src/enforcer.c`)** — rule table initialization, syscall argument decoding, threat/action selection, and statistics updates.

Supporting utilities include `src/utils.c` (CLI parsing, logging, stats printing) and `include/watchtower.h` (shared types, syscall numbers, and constants). Tests live under `tests/` and provide benign and malicious scenarios.

### Detailed Control Flow and ptrace Lifecycle
1) **Startup (`main.c`)**: initialize `tracer_context_t`, parse CLI (`-e` enforce, `-p` passive, `-d` debug, `-q` quiet), print banner, load default rules.
2) **Tracee birth (`spawn_traced_process`)**: parent `fork()`s; child calls `PTRACE_TRACEME`, self-stops with `raise(SIGSTOP)`, then `execvp()` the target. The parent `waitpid()`s the stop, sets `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC`, and begins interception.
3) **Interception loop (`run_tracer_loop`)**: uses `waitpid(child_pid, …)` to sleep until events. On syscall stop (`SIGTRAP|0x80`), it toggles `ctx->in_syscall` to distinguish entry/exit. Entry path increments `total_syscalls`, prints decoded info, and calls `evaluate_syscall()`.
4) **Syscall decoding (`decoder.c`)**: maps syscall numbers to names and categories; color-codes output to highlight process vs file vs network vs system activity. Process syscalls (`fork/clone/execve/...`) increment executions in enforcement logic.
5) **Argument harvesting (`memory.c`)**: for file-related syscalls, `enforcer` calls `read_string_from_child()` to pull path strings from the tracee’s memory; for `connect`, it uses `read_sockaddr_from_child()` (extern) to extract address/port, enabling port-based rules.
6) **Rule evaluation (`enforcer.c`)**: `evaluate_syscall()` scans `detection_rule_t` entries, matching on syscall number (or any, with `-1`) and globbed `path_pattern`. It tracks the highest-severity action: `ALLOW`, `LOG`, `ALERT`, `BLOCK`, `KILL`. Actions taken:
	- `KILL`: calls `kill_traced_process()`, increments `processes_killed`, and ends tracing.
	- `ALERT`: increments `alerts_generated` and logs.
	- `LOG`: logs only.
	- `BLOCK`: **not implemented**—a TODO; no RAX mutation occurs, so the syscall proceeds.
7) **Resume**: after handling, the tracer issues `PTRACE_SYSCALL` to continue to the next stop. Non-syscall signals are relayed back to the child with `PTRACE_SYSCALL` and the signal number.

### Detection Rules (default set in `init_default_rules`)
Rules are simple glob/path and syscall matches. Representative entries:
- **Sensitive files:** `/etc/shadow` (log/alert), `/etc/sudoers*` (alert), `/etc/passwd` (log).
- **Execution from temp:** `*/tmp/*`, `*/dev/shm/*` on `execve` (alert) to catch transient dropper behavior.
- **Log tampering:** `/var/log/*` on `unlink` (kill) to stop log wiping.
- **Process memory access:** `/proc/*/mem` on `open` (kill) to block memory dumping/tampering.
- **Cron persistence:** `/etc/cron*` (alert) to flag potential persistence attempts.
- **Network ports:** Suspicious ports {4444, 5555, 6666, 31337, 12345, 1234, 8080}; on `connect`, it increments `network_connections` and alerts or kills depending on enforce mode.

### Syscall Categorization (`decoder.c`)
- **FILE:** `open/openat/creat/unlink/mkdir/chmod/...`
- **NETWORK:** `socket/connect/accept/sendto/recvfrom/bind/listen`
- **PROCESS:** `fork/vfork/clone/execve/execveat/kill/exit`
- **SYSTEM:** everything else. Categories drive colored operator output for quick triage.

### Memory Inspection (`memory.c`)
- Performs word-wise (8-byte) reads with `PTRACE_PEEKDATA`, accumulating bytes until a null terminator or buffer limit, with checks for null pointers and small buffers. This is essential because syscall arguments are pointers in the tracee’s address space, inaccessible directly to the tracer.

### CLI and Stats (`utils.c`)
- `parse_arguments()` handles `-e/-p/-d/-q/-h/-v` and splits at `--` to identify the target program. `print_stats()` reports totals for syscalls, files accessed, network connections, executions, alerts, blocked (counter only), and killed processes.

### Tests and Samples (`tests/`)
- `test_malicious.c`: safe simulation of common malicious intents (shadow/SSH key reads, `/proc/self/mem`, cron access) to trigger alerts/kills in enforce mode.
- `test_network.c`: opens TCP/UDP sockets and attempts a localhost:80 connect; by changing the port to a suspicious one, rules fire.
- `test_file_access.c`: benign access demo to validate basic tracing.

### Design Constraints, Gaps, and Evasions
- **Descendant blindness:** The tracer sets only `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC`; it omits `PTRACE_O_TRACEFORK/CLONE/VFORK`. The main loop also calls `waitpid` on a single PID. Result: children created via `fork/clone` are never attached—an easy evasion for malware.
- **Blocking is a stub:** `ACTION_BLOCK` is logged but not enforced; RAX is never set to `-1` nor errno injected, so the syscall still completes.
- **Partial network insight:** Only `connect` increments `network_connections`; no coverage of `sendmsg/recvmsg`, TLS semantics, or DNS. Suspiciousness is a static port list—no context or reputation.
- **No thread-level coverage:** Threads created via `clone` with thread flags are not followed; per-thread syscall streams are invisible.
- **Platform assumptions:** 64-bit Linux syscall numbers and 8-byte words; no portability layer for other architectures.
- **Visibility vs. stealth:** The tracer is noisy (colored stdout) and easily detectable by ptrace-aware programs; no anti-evasion tactics (e.g., seccomp assist, LSM hooks, or hiding the tracer).

### Hardening and Extension Opportunities
- Add `PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK` and move to a `waitpid(-1, …)` loop with per-PID state to follow the full process tree.
- Implement real blocking by rewriting RAX to `-EPERM` on syscall entry when `ACTION_BLOCK` triggers.
- Expand rule language: combine syscall + path + user ID + rate limits; consider JSON-configurable rules.
- Broaden network detection: parse `sendmsg/recvmsg`, track domains/addresses, add DNS heuristics.
- Add per-thread tracing, summarize by PID/TID, and introduce sampling to manage verbosity.
- Provide optional seccomp filters to pre-filter dangerous syscalls and reduce ptrace overhead.

## Chapter 3 — Conclusion

Overwatch successfully illustrates an end-to-end ptrace EDR pipeline: attach early, decode syscalls with context, inspect userland memory to recover arguments, and run heuristic rules that can alert or terminate. Its clarity makes it a strong teaching artifact for syscall tracing and basic response logic. At the same time, major gaps (no descendant following, no actual blocking, static rules, partial network coverage) mean it is not suitable as a defensive control beyond demonstrations or labs. Advancing it toward practical use would require process-tree following, true syscall interposition, richer policy, and better observability for multi-process, multi-thread workloads. Even then, ptrace-only EDRs face inherent detectability and performance challenges compared to kernel- or eBPF-based approaches.


## References

- `ptrace(2)` Linux manual page — tracing, options, and event semantics.
- Linux x86_64 syscall table (e.g., https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/).
- `waitpid(2)` and `signal(7)` for process-stop handling and signal delivery.
- `/proc` filesystem documentation for process memory and metadata semantics.
- Project source files: `src/tracer.c`, `src/decoder.c`, `src/memory.c`, `src/enforcer.c`, `src/utils.c`, `tests/*.c`, `include/watchtower.h`.
