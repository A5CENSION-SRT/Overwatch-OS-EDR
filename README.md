# Project Watchtower 🗼

## Linux Userspace EDR (Endpoint Detection and Response)

A comprehensive system call tracer and security monitor built using Linux's `ptrace` architecture. Project Watchtower intercepts, analyzes, and enforces security policies on running processes without requiring kernel modifications.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Building](#building)
- [Usage](#usage)
- [Detection Rules](#detection-rules)
- [Technical Deep Dive](#technical-deep-dive)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Contributing](#contributing)

---

## 🎯 Overview

Project Watchtower is an educational and practical implementation of a userspace EDR system. It demonstrates how security monitoring tools can intercept and analyze process behavior without kernel modifications.

### Why Userspace?

- **Safe**: No kernel modifications that could crash the system
- **Portable**: Works on any Linux system with ptrace support
- **Educational**: Clear, well-documented implementation
- **Practical**: Real-world detection capabilities

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PROJECT WATCHTOWER                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐  │
│   │   TRACER    │◄───────►│   KERNEL    │◄───────►│   TRACEE    │  │
│   │  (Parent)   │  ptrace │ (Scheduler) │ syscall │  (Child)    │  │
│   └──────┬──────┘         └─────────────┘         └─────────────┘  │
│          │                                                          │
│   ┌──────▼──────┐                                                   │
│   │  DECODER    │  ← PTRACE_GETREGS (Read CPU Registers)           │
│   │ (Phase 2)   │                                                   │
│   └──────┬──────┘                                                   │
│          │                                                          │
│   ┌──────▼──────┐                                                   │
│   │  MEMORY     │  ← PTRACE_PEEKDATA (Read Child Memory)           │
│   │ INSPECTOR   │                                                   │
│   │ (Phase 3)   │                                                   │
│   └──────┬──────┘                                                   │
│          │                                                          │
│   ┌──────▼──────┐                                                   │
│   │  ENFORCER   │  → DECISION: Allow / Alert / Block / Kill        │
│   │ (Phase 4)   │                                                   │
│   └─────────────┘                                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### The Master/Slave Model

- **Tracer (Parent)**: The Watchtower process that monitors and makes decisions
- **Tracee (Child)**: The target process being monitored
- **Kernel**: The broker that pauses the child and signals the parent

---

## ✨ Features

### Phase 1: Process Instrumentation 🕵️
- Spawn processes with tracing enabled (`fork` + `PTRACE_TRACEME`)
- Attach to running processes (`PTRACE_ATTACH`)
- Clean detachment and signal handling

### Phase 2: Syscall Decoding 🔍
- Read CPU registers via `PTRACE_GETREGS`
- Map syscall numbers to human-readable names
- Parse arguments according to x86_64 ABI
- Handle the "Double-Stop" phenomenon (entry/exit tracking)

### Phase 3: Memory Inspection 🧠
- Cross the memory barrier using `PTRACE_PEEKDATA`
- Read strings from child's address space
- Parse complex structures (sockaddr, argv arrays)
- Word-by-word memory reconstruction

### Phase 4: Heuristic Enforcement ⚔️
- Rule-based detection engine
- Pattern matching for suspicious paths
- Threat level classification
- Enforcement actions: Log, Alert, Block, Kill

---

## 🚀 Quick Start

```bash
# Clone and build
git clone https://github.com/yourusername/Overwatch-OS-EDR.git
cd Overwatch-OS-EDR
make

# Monitor a command (passive mode)
./bin/watchtower -- ls -la

# Monitor with enforcement (kills threats)
./bin/watchtower -e -- ./suspicious_program

# Debug mode (verbose output)
./bin/watchtower -d -- cat /etc/passwd
```

---

## 🔨 Building

### Prerequisites

- GCC (or compatible C compiler)
- Linux x86_64 system
- Make

### Build Commands

```bash
# Standard build (optimized)
make

# Debug build (with symbols)
make debug

# Clean build artifacts
make clean

# Build test programs
make test-samples

# Install system-wide
sudo make install
```

### Build Output

```
bin/
├── watchtower          # Main EDR executable
├── test_file_access    # File access test
├── test_network        # Network syscall test
└── test_malicious      # Simulated malware test
```

---

## 📖 Usage

### Basic Syntax

```bash
./bin/watchtower [OPTIONS] -- PROGRAM [ARGS...]
```

### Options

| Option | Description |
|--------|-------------|
| `-e, --enforce` | Enable enforcement mode (kill malicious processes) |
| `-p, --passive` | Passive monitoring only (default) |
| `-d, --debug` | Enable debug output |
| `-q, --quiet` | Only show alerts and errors |
| `-h, --help` | Show help message |
| `-v, --version` | Show version |

### Examples

```bash
# Monitor a simple command
./bin/watchtower -- ls -la /tmp

# Monitor with full debug output
./bin/watchtower -d -- cat /etc/passwd

# Enforce security policies (will kill threats)
./bin/watchtower -e -- ./untrusted_script.sh

# Quiet mode (only alerts)
./bin/watchtower -q -- ./background_process
```

### Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║   ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗████████╗ ██████╗   ║
║   ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║╚══██╔══╝██╔═══██╗  ║
║   ██║ █╗ ██║███████║   ██║   ██║     ███████║   ██║   ██║   ██║  ║
║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║   ██║   ██║   ██║  ║
║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║   ██║   ╚██████╔╝  ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝   ║
║                                                                   ║
║              PROJECT WATCHTOWER - Linux EDR v1.0.0               ║
╚══════════════════════════════════════════════════════════════════╝

[12:34:56] [INFO ] Project Watchtower EDR starting...
[12:34:56] [INFO ] Target program: ls
[12:34:56] [INFO ] === PHASE 1: Process Instrumentation ===
[12:34:56] [INFO ] Child process created with PID 12345
[12:34:56] [INFO ] === ENTERING INTERCEPTION LOOP ===

[12:34:56] [INFO ] [FILE] openat (syscall 257)
[12:34:56] [INFO ] [FILE] read (syscall 0)
[12:34:56] [INFO ] [SYSTEM] write (syscall 1)
...

═══════════════════════════════════════════════════════════
                    SESSION STATISTICS
═══════════════════════════════════════════════════════════
  Total Syscalls Traced:     156
  Files Accessed:            23
  Network Connections:       0
  Process Executions:        1
───────────────────────────────────────────────────────────
  Alerts Generated:          0
  Syscalls Blocked:          0
  Processes Killed:          0
═══════════════════════════════════════════════════════════
```

---

## 🛡️ Detection Rules

### Built-in Rules

| Rule Name | Description | Threat Level | Action |
|-----------|-------------|--------------|--------|
| `shadow_access` | Access to /etc/shadow | CRITICAL | KILL |
| `ssh_key_access` | Access to SSH private keys | HIGH | ALERT |
| `tmp_execution` | Execution from /tmp | HIGH | KILL |
| `devshm_execution` | Execution from /dev/shm | CRITICAL | KILL |
| `netcat_execution` | Netcat/ncat execution | MEDIUM | ALERT |
| `sudoers_access` | Access to sudoers | HIGH | ALERT |
| `log_deletion` | Deleting system logs | HIGH | KILL |
| `proc_mem_access` | Direct memory access | CRITICAL | KILL |

### Suspicious Patterns Monitored

**Sensitive Files:**
- `/etc/shadow*`
- `/etc/passwd*`
- `*/.ssh/id_*`
- `*/authorized_keys`
- `/proc/*/mem`

**Suspicious Executables:**
- `/tmp/*`
- `/dev/shm/*`
- `*/netcat`, `*/nc`, `*/ncat`
- `*backdoor*`, `*reverse*shell*`

**Malicious Ports:**
- 4444 (Metasploit default)
- 5555, 6666 (Common reverse shells)
- 31337 (Elite/Back Orifice)
- 12345 (NetBus)

---

## 🔬 Technical Deep Dive

### The Context Switch (The Broker)

When we attach using ptrace, the kernel becomes a gatekeeper:

```
Child Process                    Kernel                      Parent (Watchtower)
     │                             │                              │
     │ open("/etc/shadow")         │                              │
     │────────────────────────────►│                              │
     │                             │ TASK_TRACED (stopped)        │
     │         ◄─────FROZEN────────│                              │
     │                             │─────────SIGTRAP─────────────►│
     │                             │                              │ waitpid() returns
     │                             │                              │ PTRACE_GETREGS
     │                             │◄─────────────────────────────│
     │                             │ (read registers)             │
     │                             │─────────RAX=2, RDI=0x...────►│
     │                             │                              │ DECISION: KILL
     │                             │◄────────PTRACE_KILL──────────│
     │         ◄──────SIGKILL──────│                              │
     ╳ (terminated)                │                              │
```

### The Double-Stop Phenomenon

Each syscall causes TWO stops:

1. **Entry Stop**: Registers loaded, syscall NOT executed yet
   - This is where we inspect and decide
   - RAX = syscall number
   - RDI, RSI, RDX = arguments

2. **Exit Stop**: Syscall completed
   - RAX = return value
   - We can verify success/failure

```c
// Tracking in the tracer loop
ctx->in_syscall = !ctx->in_syscall;  // Toggle on each stop
sysinfo.is_entry = ctx->in_syscall;

if (sysinfo.is_entry) {
    // Inspect arguments, make decisions
} else {
    // Check return value
}
```

### Memory Barrier (The Wormhole)

Processes have isolated virtual memory. Address `0x4000` in the child is not accessible from the parent:

```c
// WRONG - Will crash or read garbage
char *str = (char*)child_address;  // Segfault!

// CORRECT - Use ptrace to cross the barrier
unsigned long word;
word = ptrace(PTRACE_PEEKDATA, child_pid, child_address, NULL);
```

Reading strings requires multiple PEEKDATA calls:
```
Address:    0x4000    0x4008    0x4010
            ┌───────┐ ┌───────┐ ┌───────┐
Data:       │secret_│ │passwor│ │ds.txt\0│
            └───────┘ └───────┘ └───────┘
              Word 1    Word 2    Word 3
```

### x86_64 Register Map

| Register | Purpose | Example |
|----------|---------|---------|
| RAX | Syscall number / Return value | 2 (open), 59 (execve) |
| RDI | Argument 1 | Filename pointer |
| RSI | Argument 2 | Flags |
| RDX | Argument 3 | Mode/Permissions |
| R10 | Argument 4 | - |
| R8 | Argument 5 | - |
| R9 | Argument 6 | - |
| RIP | Instruction pointer | Current code location |

---

## 📁 Project Structure

```
Overwatch-OS-EDR/
├── include/
│   └── watchtower.h      # Main header with structs and prototypes
├── src/
│   ├── main.c            # Entry point, argument parsing
│   ├── tracer.c          # Phase 1: Process instrumentation
│   ├── decoder.c         # Phase 2: Syscall decoding
│   ├── memory.c          # Phase 3: Memory inspection
│   ├── enforcer.c        # Phase 4: Detection and enforcement
│   └── utils.c           # Logging, utilities
├── tests/
│   ├── test_file_access.c    # File syscall tests
│   ├── test_network.c        # Network syscall tests
│   └── test_malicious.c      # Simulated malware behavior
├── Makefile              # Build system
└── README.md             # This file
```

---

## 🧪 Testing

### Build and Run Tests

```bash
# Build test programs
make test-samples

# Run all tests
make test

# Test individual components
./bin/watchtower -- ./bin/test_file_access
./bin/watchtower -- ./bin/test_network
./bin/watchtower -e -- ./bin/test_malicious  # Will be killed!
```

### Test Scenarios

1. **File Access Test**: Monitors normal file operations
2. **Network Test**: Tracks socket creation and connections
3. **Malicious Test**: Simulates suspicious behavior (shadow access, SSH keys)

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- [ ] Add more detection rules
- [ ] Implement syscall blocking (modify RAX to -EPERM)
- [ ] Add JSON logging output
- [ ] Support for multi-threaded processes
- [ ] Configuration file for rules
- [ ] Integration with SIEM systems

---

## 📜 License

MIT License - See LICENSE file for details.

---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before monitoring processes on systems you do not own.

---

## 🙏 Acknowledgments

- Linux kernel ptrace documentation
- GDB source code for ptrace examples
- The strace project for syscall table reference

---

**Project Watchtower** - *Watching over your processes, one syscall at a time.* 🗼