"""
SessionManager — maps session IDs to live emulator instances.

Each uploaded binary gets its own (UnicornExecutor, SimulatorState) pair
stored under a UUID. This means multiple users (or the same user uploading
different binaries) don't share any state. Sessions are lightweight in
memory — the dominant cost is the Unicorn virtual memory space per session.

In a production system you'd add a TTL and a background reaper; for this
project we simply accumulate sessions until the server restarts.
"""

import uuid
import time
from typing import Optional

from ..core.state    import SimulatorState
from ..core.executor import UnicornExecutor


class Session:
    """Container for a single emulation session."""

    def __init__(self, session_id: str, binary_path: str, initial_args: list = None):
        self.session_id   = session_id
        self.binary_path  = binary_path
        self.initial_args = initial_args or []
        self.created_at   = time.time()
        self.last_used_at = time.time()

        self.state    = SimulatorState()
        self.executor = UnicornExecutor(self.state)
        if self.initial_args:
            self.executor.initial_args = self.initial_args
        self.executor.load_binary(binary_path)

    def restart(self):
        self.state    = SimulatorState()
        self.executor = UnicornExecutor(self.state)
        if self.initial_args:
            self.executor.initial_args = self.initial_args
        self.executor.load_binary(self.binary_path)
        self.last_used_at = time.time()

    # ── stdin / stdout passthroughs ──────────────────────────────
    @property
    def stdin_lines(self)  -> list: return self.executor.stdin_lines
    @property
    def stdout_lines(self) -> list: return self.executor.stdout_lines

    def push_stdin(self, text: str):
        """
        Split text into lines and append to stdin buffer.
        Supports \\xNN hex escapes so users can send binary payloads
        (e.g. overflow padding + return address).
        """
        decoded = _decode_escapes(text)
        lines   = decoded.split('\n')
        for line in lines:
            if line:  # skip blank lines from trailing newline
                self.executor.stdin_lines.append(line)

    def flush_stdout(self) -> list[str]:
        """Pop and return all pending stdout lines."""
        lines = list(self.executor.stdout_lines)
        self.executor.stdout_lines.clear()
        return lines

    def peek_stdout(self) -> list[str]:
        """Return all stdout lines without clearing them."""
        return list(self.executor.stdout_lines)

    def touch(self):
        self.last_used_at = time.time()


def _decode_escapes(s: str) -> str:
    """
    Decode C-style escape sequences in a string, including \\xNN hex escapes.
    This lets users type payloads like: AAAA\\x41\\x41\\xef\\xbe\\xad\\xde
    """
    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == 'x' and i + 3 < len(s):
                try:
                    result.append(int(s[i+2:i+4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            elif nxt == 'n':
                result.append(0x0A); i += 2; continue
            elif nxt == 't':
                result.append(0x09); i += 2; continue
            elif nxt == '\\':
                result.append(0x5C); i += 2; continue
            elif nxt == '0':
                result.append(0x00); i += 2; continue
        result.append(ord(s[i]) if isinstance(s[i], str) else s[i])
        i += 1
    return result.decode('utf-8', errors='replace')


class SessionManager:
    """Thread-unsafe singleton registry of active sessions.

    Thread-safety note: Flask's dev server is single-threaded by default,
    so a plain dict is fine. For a production deployment you'd wrap
    session access with a threading.Lock().
    """

    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def create(self, binary_path: str, initial_args: list = None) -> Session:
        sid = str(uuid.uuid4())
        session = Session(sid, binary_path, initial_args=initial_args)
        self._sessions[sid] = session
        return session

    def get(self, session_id: str) -> Optional[Session]:
        """Return a session by ID, or None if it doesn't exist."""
        session = self._sessions.get(session_id)
        if session:
            session.touch()
        return session

    def delete(self, session_id: str) -> bool:
        """Remove a session and free its resources."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def list_sessions(self) -> list:
        return [
            {
                'session_id':   s.session_id,
                'binary_path':  s.binary_path,
                'created_at':   s.created_at,
                'last_used_at': s.last_used_at,
                'instruction_count': len(s.state.instruction_history),
            }
            for s in self._sessions.values()
        ]


# Module-level singleton — imported by routes.py
session_manager = SessionManager()
