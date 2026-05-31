"""
SimulatorState — the single source of truth for CPU state.

Every other component reads from or writes to this object.
The Unicorn engine maintains its own internal register file for
accurate emulation, but after every instruction we sync Unicorn's
state back into here so the API layer never has to touch Unicorn directly.
"""

from copy import deepcopy


class SimulatorState:
    """Represents the full x86-64 CPU state at any point in time."""

    # All 16 general-purpose registers + instruction pointer
    REGISTER_NAMES = [
        'RAX', 'RBX', 'RCX', 'RDX',
        'RSI', 'RDI', 'RBP', 'RSP',
        'R8',  'R9',  'R10', 'R11',
        'R12', 'R13', 'R14', 'R15',
        'RIP',
    ]

    # The six condition flags from RFLAGS
    FLAG_NAMES = ['CF', 'PF', 'AF', 'ZF', 'SF', 'OF']

    def __init__(self):
        # All registers start zeroed — executor will set RIP/RSP on load
        self.registers = {name: 0 for name in self.REGISTER_NAMES}

        # All flags start cleared
        self.flags = {name: 0 for name in self.FLAG_NAMES}

        # Byte-addressed memory: { int address -> int byte_value }
        # We use a dict rather than a flat array because ELF binaries
        # are mapped at high addresses like 0x400000 — a flat array
        # would waste gigabytes of RAM.
        self.memory = {}

        # Stack of return addresses, populated as we detect CALL / RET
        self.call_stack = []

        # Full log of every instruction that has been executed
        self.instruction_history = []

        # Set of breakpoint addresses (int)
        self.breakpoints = set()

        # Whether emulation has finished (hit RET at top level, or error)
        self.halted = False
        self.halt_reason = None

    # ─────────────────────────────────────────────────────────────
    # REGISTER OPERATIONS
    # ─────────────────────────────────────────────────────────────

    def set_register(self, name: str, value: int):
        """Write a 64-bit value into a register, masking to 64 bits."""
        if name not in self.registers:
            raise ValueError(f"Unknown register: {name}")
        self.registers[name] = value & 0xFFFFFFFFFFFFFFFF

    def get_register(self, name: str) -> int:
        return self.registers.get(name, 0)

    # ─────────────────────────────────────────────────────────────
    # FLAG OPERATIONS
    # ─────────────────────────────────────────────────────────────

    def set_flag(self, name: str, value: int):
        if name in self.flags:
            self.flags[name] = 1 if value else 0

    def get_flag(self, name: str) -> int:
        return self.flags.get(name, 0)

    def set_rflags(self, rflags: int):
        """Unpack the RFLAGS register into individual flag fields."""
        self.flags['CF'] = (rflags >> 0)  & 1
        self.flags['PF'] = (rflags >> 2)  & 1
        self.flags['AF'] = (rflags >> 4)  & 1
        self.flags['ZF'] = (rflags >> 6)  & 1
        self.flags['SF'] = (rflags >> 7)  & 1
        self.flags['OF'] = (rflags >> 11) & 1

    # ─────────────────────────────────────────────────────────────
    # MEMORY OPERATIONS
    # ─────────────────────────────────────────────────────────────

    def set_memory(self, address: int, data: bytes):
        """Write a byte sequence into the memory map."""
        for i, byte in enumerate(data):
            self.memory[address + i] = byte & 0xFF

    def get_memory(self, address: int, size: int) -> bytes:
        """Read size bytes starting at address; unmapped bytes read as 0."""
        return bytes(self.memory.get(address + i, 0) for i in range(size))

    def get_memory_hex(self, address: int, size: int) -> str:
        return self.get_memory(address, size).hex()

    # ─────────────────────────────────────────────────────────────
    # CALL STACK TRACKING
    # ─────────────────────────────────────────────────────────────

    def push_call(self, call_site: int, target: int):
        self.call_stack.append({'call_site': call_site, 'target': target})

    def pop_call(self):
        if self.call_stack:
            return self.call_stack.pop()
        return None

    # ─────────────────────────────────────────────────────────────
    # INSTRUCTION HISTORY
    # ─────────────────────────────────────────────────────────────

    def record_instruction(self, address: int, mnemonic: str, op_str: str,
                           regs_before: dict, regs_after: dict,
                           flags_before: dict, flags_after: dict):
        self.instruction_history.append({
            'index':    len(self.instruction_history),
            'address':  address,
            'mnemonic': mnemonic,
            'op_str':   op_str,
            'regs_before':  regs_before,
            'regs_after':   regs_after,
            'flags_before': flags_before,
            'flags_after':  flags_after,
        })

    # ─────────────────────────────────────────────────────────────
    # SNAPSHOT (used by API layer)
    # ─────────────────────────────────────────────────────────────

    def get_snapshot(self) -> dict:
        """Return a deep-copied, serialisable view of the current state."""
        return {
            'registers':         deepcopy(self.registers),
            'flags':             deepcopy(self.flags),
            'call_stack':        deepcopy(self.call_stack),
            'instruction_count': len(self.instruction_history),
            'halted':            self.halted,
            'halt_reason':       self.halt_reason,
        }

    @staticmethod
    def diff_registers(before: dict, after: dict) -> list:
        """Return a list of registers whose values changed between two snapshots."""
        changed = []
        for reg in before:
            if before[reg] != after[reg]:
                changed.append({
                    'register': reg,
                    'before':   before[reg],
                    'after':    after[reg],
                })
        return changed

    @staticmethod
    def diff_flags(before: dict, after: dict) -> list:
        """Return a list of flags whose values changed between two snapshots."""
        return [
            {'flag': f, 'before': before[f], 'after': after[f]}
            for f in before
            if before[f] != after[f]
        ]
