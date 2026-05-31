"""
libc_stubs.py — Python implementations of common libc functions.

When the emulator detects execution at a PLT stub address, it calls one
of these handlers instead of trying to run actual libc code (which isn't
mapped into Unicorn's address space).

Each handler:
  - Reads arguments from x86-64 System V ABI registers (RDI, RSI, RDX, ...)
  - Performs the operation in Python (I/O via executor buffers, memory via uc)
  - Writes the return value to RAX via uc.reg_write

The STUB_BASE area is one mapped page we own entirely. We write a RET (0xC3)
at STUB_BASE + idx*8 for each function. The GOT entry for each PLT function
is patched to point to that address. When the binary CALLs printf@plt, it:
  1. Executes the PLT stub (jmp [GOT])
  2. Jumps to STUB_BASE + idx*8 (our fake code)
  3. UC_HOOK_CODE fires before the RET executes
  4. Our handler runs, sets RAX, maybe writes memory
  5. RET pops the return address, execution continues at the call site

stdin/stdout are stored as lists on UnicornExecutor so the Flask API can
read/write them without touching Unicorn directly.
"""

import struct
import ctypes


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_str(uc, addr: int, max_len: int = 4096) -> str:
    """Read a null-terminated string from Unicorn memory."""
    if addr == 0:
        return ''
    result = bytearray()
    for i in range(max_len):
        try:
            b = bytes(uc.mem_read(addr + i, 1))[0]
            if b == 0:
                break
            result.append(b)
        except Exception:
            break
    return result.decode('utf-8', errors='replace')


def _read_args(state, uc, n: int) -> list:
    """
    Read the first n function arguments per the x86-64 System V ABI.
    First 6 go in registers; the rest live on the stack above RSP.
    """
    arg_regs = ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9']
    args = [state.get_register(r) for r in arg_regs[:min(n, 6)]]
    if n > 6:
        rsp = state.get_register('RSP')
        for i in range(n - 6):
            try:
                data = bytes(uc.mem_read(rsp + 8 * (i + 1), 8))
                args.append(struct.unpack('<Q', data)[0])
            except Exception:
                args.append(0)
    return args


def _set_retval(uc, state, val: int):
    """Write a return value to RAX in both Unicorn and SimulatorState."""
    from unicorn.x86_const import UC_X86_REG_RAX
    v = val & 0xFFFFFFFFFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX, v)
    state.set_register('RAX', v)


def _write_mem(uc, state, addr: int, data: bytes):
    """Write bytes to both Unicorn memory and SimulatorState."""
    try:
        uc.mem_write(addr, data)
        state.set_memory(addr, data)
    except Exception as e:
        raise RuntimeError(f'mem_write to 0x{addr:x} failed: {e}')


def _printf_format(uc, state, fmt: str, arg_vals: list) -> str:
    """
    Minimal printf formatter covering the most common specifiers.
    Handles %d %i %u %x %X %p %s %c %% and skips %n.
    Also handles width modifiers like %016x.
    """
    out = []
    arg_idx = 0
    i = 0
    while i < len(fmt):
        if fmt[i] != '%':
            out.append(fmt[i])
            i += 1
            continue

        i += 1
        if i >= len(fmt):
            break

        # Collect flags, width, precision, length modifiers
        flags = ''
        while i < len(fmt) and fmt[i] in '-+ #0':
            flags += fmt[i]; i += 1
        width_str = ''
        while i < len(fmt) and fmt[i].isdigit():
            width_str += fmt[i]; i += 1
        prec_str = ''
        if i < len(fmt) and fmt[i] == '.':
            i += 1
            while i < len(fmt) and fmt[i].isdigit():
                prec_str += fmt[i]; i += 1
        # Length modifier
        while i < len(fmt) and fmt[i] in 'hlLqjzt':
            if i + 1 < len(fmt) and fmt[i] in 'hl' and fmt[i+1] == fmt[i]:
                i += 2
            else:
                i += 1
        if i >= len(fmt):
            break

        spec = fmt[i]; i += 1
        width = int(width_str) if width_str else 0
        val = arg_vals[arg_idx] if arg_idx < len(arg_vals) else 0
        arg_idx += 1

        if spec in 'di':
            s = str(ctypes.c_int64(val).value)
        elif spec == 'u':
            s = str(val & 0xFFFFFFFF)
        elif spec == 'x':
            s = format(val & 0xFFFFFFFFFFFFFFFF, f'0{width}x' if width and '0' in flags else 'x')
            width = 0
        elif spec == 'X':
            s = format(val & 0xFFFFFFFFFFFFFFFF, f'0{width}X' if width and '0' in flags else 'X')
            width = 0
        elif spec == 'o':
            s = oct(val & 0xFFFFFFFF)[2:]
        elif spec == 'p':
            s = f'0x{val & 0xFFFFFFFFFFFFFFFF:016x}'
        elif spec == 's':
            s = _read_str(uc, val) if val else '(null)'
        elif spec == 'c':
            c = val & 0xFF
            s = chr(c) if 32 <= c < 127 else f'\\x{c:02x}'
        elif spec == '%':
            out.append('%'); arg_idx -= 1; continue
        elif spec == 'n':
            # %n writes number of chars to pointer — skip for safety
            continue
        else:
            s = f'%{spec}'
            arg_idx -= 1

        if width and len(s) < width:
            pad = ' ' if '-' not in flags else ''
            if pad:
                s = s.rjust(width, '0' if '0' in flags else ' ')
            else:
                s = s.ljust(width)
        out.append(s)

    return ''.join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Stub dispatcher
# ─────────────────────────────────────────────────────────────────────────────

# Where we store argv string data for __libc_start_main
STUB_DATA_BASE  = 0x7F00003000


def dispatch(func_name: str, uc, state, executor) -> str:
    """
    Call the Python handler for func_name.
    Returns a log string describing what happened.
    executor exposes: .stdin_lines, .stdout_lines, .heap_top, ._mapped_ranges
    """
    fn = _HANDLERS.get(func_name)
    if fn is None:
        # Unknown function — stub it silently and return 0
        _set_retval(uc, state, 0)
        return f'stub: {func_name}() — unimplemented, returned 0'
    try:
        return fn(uc, state, executor) or f'ok: {func_name}()'
    except Exception as e:
        _set_retval(uc, state, 0)
        return f'stub: {func_name}() raised {type(e).__name__}: {e}'


# ─────────────────────────────────────────────────────────────────────────────
# Individual handlers
# ─────────────────────────────────────────────────────────────────────────────

def _h_printf(uc, state, executor):
    args = _read_args(state, uc, 7)
    fmt  = _read_str(uc, args[0])
    out  = _printf_format(uc, state, fmt, args[1:])
    executor.stdout_lines.append(out)
    _set_retval(uc, state, len(out))
    return f'printf → "{_truncate(out)}"'


def _h_printf_chk(uc, state, executor):
    # __printf_chk(flag, fmt, ...)
    args = _read_args(state, uc, 8)
    fmt  = _read_str(uc, args[1]) if len(args) > 1 else ''
    out  = _printf_format(uc, state, fmt, args[2:])
    executor.stdout_lines.append(out)
    _set_retval(uc, state, len(out))
    return f'__printf_chk → "{_truncate(out)}"'


def _h_fprintf(uc, state, executor):
    args = _read_args(state, uc, 8)
    fmt  = _read_str(uc, args[1]) if len(args) > 1 else ''
    out  = _printf_format(uc, state, fmt, args[2:])
    executor.stdout_lines.append(out)
    _set_retval(uc, state, len(out))
    return f'fprintf → "{_truncate(out)}"'


def _h_puts(uc, state, executor):
    args = _read_args(state, uc, 1)
    s    = _read_str(uc, args[0]) if args else ''
    executor.stdout_lines.append(s + '\n')
    _set_retval(uc, state, len(s) + 1)
    return f'puts("{_truncate(s)}")'


def _h_fputs(uc, state, executor):
    args = _read_args(state, uc, 2)
    s    = _read_str(uc, args[0]) if args else ''
    executor.stdout_lines.append(s)
    _set_retval(uc, state, len(s))
    return f'fputs("{_truncate(s)}")'


def _h_putchar(uc, state, executor):
    args = _read_args(state, uc, 1)
    c    = args[0] & 0xFF if args else 0x3F
    ch   = chr(c) if 32 <= c < 127 else (f'\\n' if c == 10 else f'\\x{c:02x}')
    executor.stdout_lines.append(chr(c) if c < 128 else '?')
    _set_retval(uc, state, c)
    return f'putchar({ch!r})'


def _h_gets(uc, state, executor):
    args = _read_args(state, uc, 1)
    buf_addr = args[0] if args else 0

    if not executor.stdin_lines:
        executor.waiting_for_input  = True
        executor.pending_input_func = 'gets'
        executor.pending_input_args = {'buf_addr': buf_addr}
        uc.emu_stop()
        return 'gets() → WAITING FOR INPUT'

    line = executor.stdin_lines.pop(0)
    data = line.encode('utf-8', errors='replace') + b'\x00'
    try:
        _write_mem(uc, state, buf_addr, data)
    except Exception as e:
        executor.stdout_lines.append(f'[gets write failed: {e}]\n')
        _set_retval(uc, state, 0); return f'gets() → write error'

    executor.stdout_lines.append(line + '\n')
    _set_retval(uc, state, buf_addr)
    return f'gets() → "{_truncate(line)}" → 0x{buf_addr:x}'


def _h_fgets(uc, state, executor):
    args    = _read_args(state, uc, 3)
    buf_addr = args[0] if args else 0
    n        = args[1] if len(args) > 1 else 256

    if not executor.stdin_lines:
        executor.waiting_for_input  = True
        executor.pending_input_func = 'fgets'
        executor.pending_input_args = {'buf_addr': buf_addr, 'max_len': n}
        uc.emu_stop()
        return 'fgets() → WAITING FOR INPUT'

    line = executor.stdin_lines.pop(0)
    s    = (line[:n - 2] + '\n').encode('utf-8', errors='replace') + b'\x00'
    try:
        _write_mem(uc, state, buf_addr, s)
    except Exception as e:
        _set_retval(uc, state, 0); return f'fgets() write failed: {e}'

    executor.stdout_lines.append(line + '\n')
    _set_retval(uc, state, buf_addr)
    return f'fgets() → "{_truncate(line)}"'


def _h_scanf(uc, state, executor):
    args    = _read_args(state, uc, 5)
    fmt_str = _read_str(uc, args[0]) if args else ''

    if not executor.stdin_lines:
        executor.waiting_for_input  = True
        executor.pending_input_func = 'scanf'
        executor.pending_input_args = {'fmt': fmt_str}
        uc.emu_stop()
        return 'scanf() → WAITING FOR INPUT'

    line  = executor.stdin_lines.pop(0)
    tokens = line.split()
    tok_idx = 0
    matched = 0
    i = 0
    while i < len(fmt_str) and tok_idx < len(tokens):
        if fmt_str[i] == '%' and i + 1 < len(fmt_str):
            spec  = fmt_str[i + 1]; i += 2
            dest  = args[matched + 1] if matched + 1 < len(args) else 0
            token = tokens[tok_idx]; tok_idx += 1
            try:
                if spec in 'di':
                    v = ctypes.c_int(int(token)).value
                    _write_mem(uc, state, dest, struct.pack('<i', v))
                elif spec == 'u':
                    _write_mem(uc, state, dest, struct.pack('<I', int(token) & 0xFFFFFFFF))
                elif spec in 'xX':
                    _write_mem(uc, state, dest, struct.pack('<I', int(token, 16) & 0xFFFFFFFF))
                elif spec == 's':
                    _write_mem(uc, state, dest, token.encode() + b'\x00')
                matched += 1
            except Exception:
                pass
        else:
            i += 1

    executor.stdout_lines.append(line + '\n')
    _set_retval(uc, state, matched)
    return f'scanf("{fmt_str}") → {matched} items matched'


def _h_system(uc, state, executor):
    args = _read_args(state, uc, 1)
    cmd  = _read_str(uc, args[0]) if args else ''
    msg  = f'[system("{cmd}") called — stubbed, not executed]\n'
    executor.stdout_lines.append(msg)
    _set_retval(uc, state, 0)
    return f'system("{_truncate(cmd)}") → stubbed'


def _h_exit(uc, state, executor):
    args = _read_args(state, uc, 1)
    code = args[0] & 0xFF if args else 0
    executor.stdout_lines.append(f'[exit({code}) called]\n')
    state.halted      = True
    state.halt_reason = f'exit({code}) called'
    _set_retval(uc, state, 0)
    return f'exit({code})'


def _h_abort(uc, state, executor):
    executor.stdout_lines.append('[abort() called]\n')
    state.halted      = True
    state.halt_reason = 'abort() called'
    _set_retval(uc, state, 0)
    return 'abort()'


def _h_malloc(uc, state, executor):
    args = _read_args(state, uc, 1)
    size = args[0] if args else 0
    if size == 0:
        _set_retval(uc, state, 0)
        return 'malloc(0) → NULL'
    ptr = executor.heap_alloc(size)
    _set_retval(uc, state, ptr)
    return f'malloc({size}) → 0x{ptr:x}'


def _h_calloc(uc, state, executor):
    args  = _read_args(state, uc, 2)
    total = (args[0] if args else 0) * (args[1] if len(args) > 1 else 0)
    if total == 0:
        _set_retval(uc, state, 0)
        return 'calloc → NULL'
    ptr = executor.heap_alloc(total, zero=True)
    _set_retval(uc, state, ptr)
    return f'calloc → 0x{ptr:x}'


def _h_realloc(uc, state, executor):
    args    = _read_args(state, uc, 2)
    new_sz  = args[1] if len(args) > 1 else 0
    if new_sz == 0:
        _set_retval(uc, state, 0)
        return 'realloc(_, 0) → NULL'
    ptr = executor.heap_alloc(new_sz)
    _set_retval(uc, state, ptr)
    return f'realloc → 0x{ptr:x}'


def _h_free(uc, state, executor):
    _set_retval(uc, state, 0)
    return 'free() → noop'


def _h_strlen(uc, state, executor):
    args = _read_args(state, uc, 1)
    s    = _read_str(uc, args[0]) if args else ''
    _set_retval(uc, state, len(s))
    return f'strlen → {len(s)}'


def _h_strcpy(uc, state, executor):
    args = _read_args(state, uc, 2)
    dst, src = (args[0] if args else 0), (args[1] if len(args) > 1 else 0)
    s = _read_str(uc, src).encode('utf-8', errors='replace') + b'\x00'
    try:
        _write_mem(uc, state, dst, s)
    except Exception:
        pass
    _set_retval(uc, state, dst)
    return f'strcpy → {len(s)-1} chars'


def _h_strncpy(uc, state, executor):
    args = _read_args(state, uc, 3)
    dst  = args[0] if args else 0
    src  = args[1] if len(args) > 1 else 0
    n    = args[2] if len(args) > 2 else 0
    s    = _read_str(uc, src, n).encode('utf-8', errors='replace')[:n].ljust(n, b'\x00')
    try:
        _write_mem(uc, state, dst, s)
    except Exception:
        pass
    _set_retval(uc, state, dst)
    return f'strncpy({n} bytes)'


def _h_strcmp(uc, state, executor):
    args = _read_args(state, uc, 2)
    s1   = _read_str(uc, args[0]) if args else ''
    s2   = _read_str(uc, args[1]) if len(args) > 1 else ''
    _set_retval(uc, state, 0 if s1 == s2 else (1 if s1 > s2 else 0xFFFFFFFFFFFFFFFF))
    return f'strcmp → {"eq" if s1==s2 else "ne"}'


def _h_strncmp(uc, state, executor):
    args = _read_args(state, uc, 3)
    n    = args[2] if len(args) > 2 else 0
    s1   = _read_str(uc, args[0])[:n] if args else ''
    s2   = _read_str(uc, args[1])[:n] if len(args) > 1 else ''
    _set_retval(uc, state, 0 if s1 == s2 else (1 if s1 > s2 else 0xFFFFFFFFFFFFFFFF))
    return f'strncmp({n}) → {"eq" if s1==s2 else "ne"}'


def _h_strcat(uc, state, executor):
    args    = _read_args(state, uc, 2)
    dst, src = (args[0] if args else 0), (args[1] if len(args) > 1 else 0)
    dst_len = len(_read_str(uc, dst))
    src_s   = _read_str(uc, src).encode('utf-8', errors='replace') + b'\x00'
    try:
        _write_mem(uc, state, dst + dst_len, src_s)
    except Exception:
        pass
    _set_retval(uc, state, dst)
    return 'strcat'


def _h_strncat(uc, state, executor):
    args      = _read_args(state, uc, 3)
    dst, src  = (args[0] if args else 0), (args[1] if len(args) > 1 else 0)
    n         = args[2] if len(args) > 2 else 0
    dst_len   = len(_read_str(uc, dst))
    src_s     = _read_str(uc, src, n)[:n].encode('utf-8', errors='replace') + b'\x00'
    try:
        _write_mem(uc, state, dst + dst_len, src_s)
    except Exception:
        pass
    _set_retval(uc, state, dst)
    return f'strncat({n})'


def _h_memset(uc, state, executor):
    args = _read_args(state, uc, 3)
    ptr  = args[0] if args else 0
    c    = args[1] & 0xFF if len(args) > 1 else 0
    n    = args[2] if len(args) > 2 else 0
    try:
        _write_mem(uc, state, ptr, bytes([c] * n))
    except Exception:
        pass
    _set_retval(uc, state, ptr)
    return f'memset(ptr=0x{ptr:x}, c=0x{c:02x}, n={n})'


def _h_memcpy(uc, state, executor):
    args     = _read_args(state, uc, 3)
    dst, src = (args[0] if args else 0), (args[1] if len(args) > 1 else 0)
    n        = args[2] if len(args) > 2 else 0
    try:
        data = bytes(uc.mem_read(src, n))
        _write_mem(uc, state, dst, data)
    except Exception:
        pass
    _set_retval(uc, state, dst)
    return f'memcpy({n} bytes)'


def _h_memmove(uc, state, executor):
    return _h_memcpy(uc, state, executor)


def _h_memcmp(uc, state, executor):
    args    = _read_args(state, uc, 3)
    s1, s2  = (args[0] if args else 0), (args[1] if len(args) > 1 else 0)
    n       = args[2] if len(args) > 2 else 0
    try:
        b1 = bytes(uc.mem_read(s1, n))
        b2 = bytes(uc.mem_read(s2, n))
        _set_retval(uc, state, 0 if b1 == b2 else (1 if b1 > b2 else 0xFFFFFFFFFFFFFFFF))
    except Exception:
        _set_retval(uc, state, 0)
    return 'memcmp'


def _h_atoi(uc, state, executor):
    args = _read_args(state, uc, 1)
    s    = _read_str(uc, args[0]).strip() if args else ''
    try:
        v = ctypes.c_int(int(s)).value
    except Exception:
        v = 0
    _set_retval(uc, state, v)
    return f'atoi("{s}") → {v}'


def _h_strtol(uc, state, executor):
    args = _read_args(state, uc, 3)
    s    = _read_str(uc, args[0]).strip() if args else ''
    base = args[2] if len(args) > 2 else 10
    try:
        v = int(s, base if base != 0 else 10)
    except Exception:
        v = 0
    _set_retval(uc, state, v & 0xFFFFFFFFFFFFFFFF)
    return f'strtol("{s}", base={base}) → {v}'


def _h_sleep(uc, state, executor):
    # Never actually sleep in the emulator
    _set_retval(uc, state, 0)
    return 'sleep() → stubbed'


def _h_stack_chk_fail(uc, state, executor):
    """Stack canary smashed — libc would call this to abort."""
    msg = '*** stack smashing detected *** __stack_chk_fail called\n'
    executor.stdout_lines.append(msg)
    state.halted      = True
    state.halt_reason = '__stack_chk_fail: stack canary overwritten'
    _set_retval(uc, state, 0)
    return 'STACK CANARY OVERWRITTEN'


def _h_libc_start_main(uc, state, executor):
    """
    __libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)

    The real function sets up the C runtime environment and then calls main().
    We stub it by:
      1. Reading the main() pointer from RDI (first arg)
      2. Setting up fake argc=1 / argv=["emulator"] in the stub data page
      3. Patching the return address on the stack to point to main()
         so when our stub's RET fires, execution goes there
      4. Setting RDI/RSI/RDX for main(argc, argv, envp)
    """
    from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RSI,
                                    UC_X86_REG_RDX, UC_X86_REG_RSP)

    args     = _read_args(state, uc, 3)
    main_ptr = args[0] if args else 0

    if main_ptr == 0:
        state.halted      = True
        state.halt_reason = '__libc_start_main: NULL main pointer'
        return '__libc_start_main: NULL main'

    # Write argv data into the stub data page
    argv0   = b'/emulator\x00'
    try:
        _write_mem(uc, state, STUB_DATA_BASE,        argv0)
        _write_mem(uc, state, STUB_DATA_BASE + 0x10,
                   struct.pack('<QQ', STUB_DATA_BASE, 0))  # argv[0], NULL
    except Exception as e:
        pass  # data page might not be mapped yet; handled gracefully below

    # Set up registers for main(argc, argv_ptr, NULL)
    argc    = getattr(executor, '_argc', 1)
    argv_p  = getattr(executor, '_argv_ptr', STUB_DATA_BASE + 0x10)
    uc.reg_write(UC_X86_REG_RDI, argc)
    uc.reg_write(UC_X86_REG_RSI, argv_p)
    uc.reg_write(UC_X86_REG_RDX, 0)
    state.set_register('RDI', argc)
    state.set_register('RSI', argv_p)
    state.set_register('RDX', 0)

    # Patch the return address on the stack:
    # [RSP+0] = main_ptr  ← stub's RET pops this, jumps to main; RSP becomes rsp+8
    # [RSP+8] = sentinel  ← main's RET pops this; our fetch-unmapped hook catches it
    rsp = state.get_register('RSP')
    try:
        _write_mem(uc, state, rsp,     struct.pack('<Q', main_ptr))
        _write_mem(uc, state, rsp + 8, struct.pack('<Q', 0))
    except Exception as e:
        state.halted      = True
        state.halt_reason = f'__libc_start_main: stack setup failed: {e}'
        return f'__libc_start_main: stack error: {e}'

    _set_retval(uc, state, 0)
    return f'__libc_start_main → main @ 0x{main_ptr:x}'


def _truncate(s: str, n: int = 40) -> str:
    s = s.replace('\n', '\\n').replace('\r', '\\r')
    return s[:n] + '…' if len(s) > n else s


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch table
# ─────────────────────────────────────────────────────────────────────────────

_HANDLERS = {
    # I/O output
    'printf':                   _h_printf,
    '__printf_chk':             _h_printf_chk,
    'fprintf':                  _h_fprintf,
    '__fprintf_chk':            _h_fprintf,
    'puts':                     _h_puts,
    'fputs':                    _h_fputs,
    'fwrite':                   _h_fputs,
    'putchar':                  _h_putchar,
    'putchar_unlocked':         _h_putchar,
    'fflush':                   lambda uc,st,ex: (_set_retval(uc,st,0), 'fflush noop')[1],
    'perror':                   _h_puts,
    # I/O input
    'gets':                     _h_gets,
    'fgets':                    _h_fgets,
    'scanf':                    _h_scanf,
    '__isoc99_scanf':           _h_scanf,
    # Process control
    'system':                   _h_system,
    'exit':                     _h_exit,
    '_exit':                    _h_exit,
    '__exit':                   _h_exit,
    'abort':                    _h_abort,
    'sleep':                    _h_sleep,
    'usleep':                   _h_sleep,
    # Memory
    'malloc':                   _h_malloc,
    'calloc':                   _h_calloc,
    'realloc':                  _h_realloc,
    'free':                     _h_free,
    # String
    'strlen':                   _h_strlen,
    'strcpy':                   _h_strcpy,
    'strncpy':                  _h_strncpy,
    'strcmp':                   _h_strcmp,
    'strncmp':                  _h_strncmp,
    'strcat':                   _h_strcat,
    'strncat':                  _h_strncat,
    # Memory ops
    'memset':                   _h_memset,
    'memcpy':                   _h_memcpy,
    'memmove':                  _h_memmove,
    'memcmp':                   _h_memcmp,
    '__memset_chk':             _h_memset,
    '__memcpy_chk':             _h_memcpy,
    # Conversion
    'atoi':                     _h_atoi,
    'atol':                     _h_atoi,
    'strtol':                   _h_strtol,
    'strtoul':                  _h_strtol,
    # Safety / runtime
    '__stack_chk_fail':         _h_stack_chk_fail,
    '__libc_start_main':        _h_libc_start_main,
    '__libc_start_main_impl':   _h_libc_start_main,
    # GCC internals — safe to stub
    '__gmon_start__':           lambda uc,st,ex: (_set_retval(uc,st,0), '__gmon_start__ noop')[1],
    '_ITM_registerTMCloneTable':lambda uc,st,ex: (_set_retval(uc,st,0), 'ITM noop')[1],
    '_ITM_deregisterTMCloneTable':lambda uc,st,ex: (_set_retval(uc,st,0), 'ITM noop')[1],
}
