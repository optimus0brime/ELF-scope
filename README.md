# ELFscope

> A web-based x86-64 CPU emulator and debugger dashboard. Load any ELF binary, step through it instruction by instruction, and watch registers, flags, memory, and the stack update in real time.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

Built for exploit development, malware analysis, and low-level systems education. ELFscope intercepts execution at the PLT boundary so libc is never needed — `printf` output appears in the terminal panel, `gets` and `scanf` pause and prompt you for input in real time, and everything runs inside [Unicorn Engine](https://www.unicorn-engine.org/) with hooks into every instruction, memory access, and syscall.

---

## Screenshot

```
┌─ ELFscope ─────────────────────────────────── RUNNING ──┐
│ DISASSEMBLY                             RIP: 0x00401176  │
│   0x00401160  push   rbp                                 │
│   0x00401161  mov    rbp, rsp                            │
│ ► 0x00401164  call   printf@plt                          │
│   0x00401169  lea    rax, [rbp-0x40]                     │
│   0x0040116d  mov    rdi, rax                            │
│   0x00401170  call   gets@plt          ← WAITING INPUT   │
├─ TERMINAL ──────────────────────────────────────────────┤
│  === Stack BOF Demo ===                                  │
│  secret() @ 0x401142                                     │
│  Input:                                                  │
│  stdin> AAAA\x41\x41\x41\x41\x42\x11\x40\x00_          │
└─────────────────────────────────────────────────────────┘
```

---

## Features

### Execution Engine
- Full x86-64 ISA via Unicorn Engine — 600+ instructions
- Step one instruction at a time or run continuously
- Pause, resume, and **restart** without re-uploading the binary
- Pre-load `argv` arguments before execution starts
- Keyboard shortcuts: `s` step · `r` run · `p` pause · `Shift+R` restart

### Live CPU Dashboard
- All 16 general-purpose registers — hex + decimal, **yellow flash on change**
- Six condition flags (CF, ZF, SF, OF, PF, AF) with live toggle state
- Disassembly context pane — 30 instructions centered on RIP, auto-scrolling
- `►` arrow marks the current instruction; mnemonics color-coded by type
- Call stack tracker, instruction history log, memory hexdump panel

### Dynamic Binary Support — No libc Needed
ELFscope parses `.rela.plt` at load time and patches each GOT entry to point to a Python stub. No dynamic linker. No libc on disk.

| Category | Stubbed Functions |
|---|---|
| Output | `printf` `fprintf` `puts` `putchar` `fputs` |
| Input | `gets` `fgets` `scanf` |
| Memory | `malloc` `calloc` `realloc` `free` |
| String | `strlen` `strcpy` `strcmp` `memset` `memcpy` `strcat` `strncat` |
| Process | `system` `exit` `abort` `__libc_start_main` `__stack_chk_fail` |

### Pause-on-Input
When `gets()`, `fgets()`, or `scanf()` is called and stdin is empty, ELFscope calls `uc.emu_stop()` inside the Unicorn hook — execution halts cleanly, the terminal panel glows green, and you type the input directly. Hit Enter and execution resumes from exactly where it stopped. If **Run** mode was active, it restarts automatically after input.

### stdin Payload Support
Pre-queue input lines before running. Supports `\xNN` hex escapes for binary payloads:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x42\x11\x40\x00\x00\x00\x00\x00
```

### Halt Behavior
- Normal exits show a green ✅ inline banner — no blocking overlay
- Error halts (bad memory, invalid instruction, stack smash) show a red 🛑 banner with exact reason
- **Restart** re-runs the same binary fresh — no re-upload

---

## Quick Start

```bash
# Install dependencies
pip install unicorn capstone pyelftools flask flask-cors

# Run
python run.py
```

Open `http://localhost:5000`. Drop any x86-64 ELF binary onto the upload area.

A test binary is included at `backend/tests/binaries/test_add.elf` — a static binary that adds 10 + 32 and returns 42, good for verifying the setup.

---

## Stack Buffer Overflow Demo

Compile a vulnerable binary:

```c
// bof.c
#include <stdio.h>
char *gets(char *s);

void secret() {
    printf("[!] secret() reached\n");
    system("/bin/sh");
}
void vuln() {
    char buf[64];
    printf("Input: ");
    gets(buf);
}
int main() {
    printf("secret() @ %p\n", (void *)secret);
    vuln();
    return 0;
}
```

```bash
gcc -O0 -no-pie -fno-stack-protector bof.c -o bof.elf
```

Load `bof.elf` in ELFscope. The terminal prints `secret() @ 0x401142`. Type your payload in the stdin panel using the address shown:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x42\x11\x40\x00\x00\x00\x00\x00
```

The return address overwrites. When `vuln()` returns, RIP jumps to `secret()`. The terminal shows `[system("/bin/sh") called — stubbed]`. The halt banner shows the hijacked RIP. The entire overflow is visible in the register panel, step by step.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              WEB DASHBOARD  (Vanilla JS)                │
│   Disasm · Registers · Flags · Terminal · Tabs          │
└────────────────────────┬────────────────────────────────┘
                         │  HTTP REST
┌────────────────────────▼────────────────────────────────┐
│                   FLASK API                             │
│  /execute  /step  /state  /memory  /disasm              │
│  /stdin    /resume  /restart  /history  /register       │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              SIMULATOR STATE LAYER                      │
│  SimulatorState — registers, flags, memory, history     │
│  SessionManager — one (executor, state) pair per upload │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              EXECUTION ENGINE                           │
│  UnicornExecutor — ELF load, PLT patch, step, resume    │
│  LibcStubs       — Python handlers for libc functions   │
│  BinaryLoader    — ELF segment + relocation parsing     │
└─────────────────────────────────────────────────────────┘
```

**SimulatorState** is the single source of truth. Unicorn maintains its own internal register file for accurate emulation; after every instruction, `_sync_from_unicorn()` mirrors it back. The API layer reads exclusively from SimulatorState and never touches Unicorn directly — keeping the two cleanly decoupled.

**PLT interception** writes a single `RET` byte at a stub page (`0x7F00001000+`), patches each GOT entry there, and uses `UC_HOOK_CODE` to dispatch to a Python handler before the RET fires. Handlers read arguments from RDI/RSI/RDX per the System V ABI, write the return value to RAX, and let RET pop the return address naturally.

**Pause-on-input** calls `uc.emu_stop()` from inside the gets() hook when stdin is empty. The step response returns `waiting_for_input: true`. `/api/resume` writes the user's text to the buffer address, simulates the RET by reading `[RSP]` and advancing RIP + RSP, then returns a normal step result.

---

## Project Structure

```
elfscope/
├── run.py                          # Single-command startup
├── requirements.txt
│
├── backend/
│   ├── app.py                      # Flask application factory
│   ├── core/
│   │   ├── executor.py             # Unicorn wrapper, PLT patching, pause-on-input
│   │   ├── state.py                # CPU state machine
│   │   ├── loader.py               # ELF segment + symbol parser
│   │   └── libc_stubs.py           # Python libc function implementations
│   └── api/
│       ├── routes.py               # All REST endpoints
│       └── session_manager.py      # Session lifecycle management
│
└── frontend/
    ├── index.html                  # Dashboard layout
    ├── css/style.css               # WinDbg-style theme
    └── js/
        ├── constants.js            # Shared constants
        ├── api.js                  # Fetch wrappers for all endpoints
        ├── logger.js               # Log panel with level filtering
        ├── state_renderer.js       # Disasm, registers, flags, memory rendering
        └── ui.js                   # Event wiring, step/run/pause/restart/input
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/execute` | Upload ELF binary, create session, return initial state |
| `POST` | `/api/step/<sid>` | Execute one instruction, return diff |
| `GET`  | `/api/state/<sid>` | Full current CPU state |
| `GET`  | `/api/memory/<sid>?address=&size=` | Hexdump of any memory range |
| `GET`  | `/api/disasm/<sid>?address=&count=` | Disassemble N instructions at address |
| `POST` | `/api/stdin/<sid>` | Queue stdin lines (supports `\xNN` hex escapes) |
| `POST` | `/api/resume/<sid>` | Resume after pause-on-input with provided text |
| `POST` | `/api/restart/<sid>` | Re-run same binary, completely fresh state |
| `POST` | `/api/register/<sid>` | Overwrite a register value at runtime |
| `GET`  | `/api/history/<sid>` | Instruction execution log |
| `DELETE` | `/api/session/<sid>` | Destroy session and free resources |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| CPU emulation | [Unicorn Engine](https://www.unicorn-engine.org/) 2.x |
| Disassembly | [Capstone](https://www.capstone-engine.org/) 5.x |
| ELF parsing | [pyelftools](https://github.com/eliben/pyelftools) |
| Backend | [Flask](https://flask.palletsprojects.com/) 2.x + flask-cors |
| Frontend | Vanilla JS — no build step, no framework |
| Python | 3.9+ |

---

## Roadmap

- [ ] Taint tracking — mark attacker-controlled bytes and propagate through execution
- [ ] Stack layout visualizer — frame boundaries, canary, saved RBP, return address rendered as a spatial diagram
- [ ] ROP gadget scanner and chain builder
- [ ] Syscall trace log (strace-style timeline)
- [ ] Memory snapshot diff — compare any two execution points byte-by-byte
- [ ] Code coverage heatmap over disassembly
- [ ] Shadow stack — detect return address overwrites the moment they happen
- [ ] Cache + pipeline simulation (COA teaching mode)
- [ ] ASLR simulation with infoleak workflow
- [ ] Heap visualization (chunk headers, free list, bin state)

---

## Use Cases

**Exploit development** — craft a payload in the stdin panel with hex escapes, step through the overflow, verify RIP control, iterate without restarting your environment.

**Malware analysis** — step through a suspicious binary without executing it natively; every syscall is logged, every library call is intercepted, nothing touches your real filesystem or network.

**Systems education** — make x86-64 calling conventions, stack frames, condition flags, and memory layout observable rather than abstract. Every concept in a systems security or COA course becomes something you can watch happen.

**CTF prep** — understand what a binary does before writing the exploit, with full register and memory visibility at every step.

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">Built with Unicorn · Capstone · Flask</p>
