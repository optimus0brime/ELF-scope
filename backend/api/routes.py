"""
Flask route handlers — all five REST endpoints.

Design principle: routes are thin. They validate the request, delegate
to the session manager and executor, then serialize the response.
No business logic lives here — that all lives in core/.

Endpoints:
  POST   /api/execute                 Upload binary, create session
  POST   /api/step/<session_id>       Execute one instruction
  GET    /api/state/<session_id>      Full CPU state
  GET    /api/memory/<session_id>     Hexdump of a memory range
  POST   /api/register/<session_id>   Overwrite a register value
  DELETE /api/session/<session_id>    Destroy session
  GET    /api/sessions                List active sessions
  GET    /api/history/<session_id>    Instruction history log
"""

import os
import tempfile

from flask import Blueprint, request, jsonify, current_app

from .session_manager import session_manager

api = Blueprint('api', __name__, url_prefix='/api')


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _session_or_404(session_id: str):
    """Fetch a session or return a 404 JSON error."""
    session = session_manager.get(session_id)
    if not session:
        return None, (jsonify({'error': f'Session not found: {session_id}'}), 404)
    return session, None


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/execute
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/execute', methods=['POST'])
def execute():
    """
    Upload a binary, create a session, and return the initial CPU state.

    The binary is saved to a temp file so it persists for the duration of
    the session (Unicorn memory-maps it; we need the file to stay around).
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded (field name: file)'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400

    # Save to a temp file (we keep a reference so it isn't cleaned up)
    upload_dir = current_app.config.get('UPLOAD_DIR', '/tmp/emulator_uploads')
    os.makedirs(upload_dir, exist_ok=True)

    tmp = tempfile.NamedTemporaryFile(
        dir=upload_dir, delete=False,
        suffix=f'_{f.filename}'
    )
    f.save(tmp.name)
    tmp.close()

    # Parse optional args string (space-separated, e.g. "arg1 arg2")
    args_str = request.form.get('args', '').strip()
    if args_str:
        import shlex
        try:   initial_args = shlex.split(args_str)
        except Exception: initial_args = args_str.split()
    else:
        initial_args = []

    try:
        session = session_manager.create(tmp.name, initial_args=initial_args)
    except ValueError as e:
        os.unlink(tmp.name)
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        os.unlink(tmp.name)
        return jsonify({'error': f'Failed to load binary: {e}'}), 500

    info = session.executor.get_binary_info()
    state = session.state.get_snapshot()

    return jsonify({
        'session_id':  session.session_id,
        'filename':    f.filename,
        'entry_point': f'0x{info["entry_point"]:016x}',
        'arch':        info.get('arch', 'x64'),
        'sections':    info.get('sections', []),
        'symbols':     info.get('symbols', []),
        'state':       state,
    }), 201


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/step/<session_id>
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/step/<session_id>', methods=['POST'])
def step(session_id):
    """
    Execute one instruction and return a rich diff of what changed.

    The response includes the disassembled instruction, full before/after
    state snapshots, and lists of registers/flags that changed — so the
    frontend can highlight exactly what the instruction touched.
    """
    session, err = _session_or_404(session_id)
    if err:
        return err

    result = session.executor.execute_one_instruction()

    # Attach any new stdout produced during this step
    # (already included by executor, but ensure it's always present)
    result.setdefault('new_output', [])
    result.setdefault('stub_log',   None)

    if 'error' in result:
        return jsonify(result), 200   # still 200 — UI handles halted state

    return jsonify(result), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/state/<session_id>
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/state/<session_id>', methods=['GET'])
def get_state(session_id):
    """Return the full current CPU state without advancing execution."""
    session, err = _session_or_404(session_id)
    if err:
        return err

    return jsonify(session.state.get_snapshot()), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/memory/<session_id>?address=0x...&size=N
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/memory/<session_id>', methods=['GET'])
def get_memory(session_id):
    """
    Return a hexdump of a memory range.

    Query params:
      address  — start address (hex string, e.g. 0x400000)
      size     — number of bytes (decimal, max 1024)
    """
    session, err = _session_or_404(session_id)
    if err:
        return err

    addr_str = request.args.get('address', '0x400000')
    size_str = request.args.get('size', '64')

    try:
        address = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
    except ValueError:
        return jsonify({'error': f'Invalid address: {addr_str}'}), 400

    try:
        size = min(int(size_str), 1024)   # cap at 1 KB per request
    except ValueError:
        return jsonify({'error': f'Invalid size: {size_str}'}), 400

    data = session.executor.read_memory(address, size)

    # Return both a flat hex string and a structured row-by-row view
    # (16 bytes per row, matching classic hexdump output)
    rows = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        rows.append({
            'address': f'0x{address + offset:016x}',
            'hex':     ' '.join(f'{b:02x}' for b in chunk),
            'ascii':   ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk),
        })

    return jsonify({
        'address': f'0x{address:016x}',
        'size':    size,
        'hex':     data.hex(),
        'rows':    rows,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/register/<session_id>   { "register": "RAX", "value": "0x42" }
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/register/<session_id>', methods=['POST'])
def set_register(session_id):
    """
    Overwrite a register value — the 'edit register' feature.
    Writes to both SimulatorState and Unicorn's internal register file
    so they stay in sync.
    """
    session, err = _session_or_404(session_id)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    reg  = body.get('register', '').upper()
    val  = body.get('value', '')

    if not reg:
        return jsonify({'error': 'Missing "register" field'}), 400

    try:
        value = int(val, 16) if isinstance(val, str) and val.startswith('0x') \
                else int(val)
    except (ValueError, TypeError):
        return jsonify({'error': f'Invalid value: {val}'}), 400

    try:
        session.executor.set_register(reg, value)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({
        'register': reg,
        'value':    value,
        'state':    session.state.get_snapshot(),
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/history/<session_id>
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/history/<session_id>', methods=['GET'])
def get_history(session_id):
    """
    Return the instruction history log.
    Accepts an optional ?limit=N query param (default 100, max 1000).
    """
    session, err = _session_or_404(session_id)
    if err:
        return err

    limit = min(int(request.args.get('limit', 100)), 1000)
    history = session.state.instruction_history[-limit:]

    # Strip the full register snapshots to keep the payload small —
    # just return the address, mnemonic, and operand string.
    summary = [
        {
            'index':    h['index'],
            'address':  f'0x{h["address"]:016x}',
            'mnemonic': h['mnemonic'],
            'op_str':   h['op_str'],
        }
        for h in history
    ]
    return jsonify({'history': summary, 'total': len(session.state.instruction_history)}), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/stdin/<session_id>   { "text": "..." }
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/stdin/<session_id>', methods=['POST'])
def send_stdin(session_id):
    """
    Push text into the session's stdin buffer.

    The text field supports \\xNN hex escapes for binary payloads.
    Example: "AAAA\\x41\\x41\\xef\\xbe\\xad\\xde\\x00\\x40"

    Lines are split on newlines; each becomes one gets()/read() response.
    """
    session, err = _session_or_404(session_id)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    text = body.get('text', '')
    if not text:
        return jsonify({'error': 'Missing "text" field'}), 400

    session.push_stdin(text)
    return jsonify({
        'queued':      len(session.stdin_lines),
        'stdin_lines': session.stdin_lines,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/stdout/<session_id>
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/stdout/<session_id>', methods=['GET'])
def get_stdout(session_id):
    """
    Return (and optionally flush) pending stdout lines.
    Add ?flush=1 to clear the buffer after reading.
    """
    session, err = _session_or_404(session_id)
    if err:
        return err

    flush = request.args.get('flush', '0') == '1'
    if flush:
        lines = session.flush_stdout()
    else:
        lines = session.peek_stdout()

    return jsonify({
        'lines':  lines,
        'joined': ''.join(lines),
    }), 200

@api.route('/disasm/<session_id>', methods=['GET'])
def disasm(session_id):
    """Disassemble N instructions from a given address (for context view)."""
    session, err = _session_or_404(session_id)
    if err: return err
    addr_str = request.args.get('address', '0x0')
    count    = min(int(request.args.get('count', '30')), 60)
    try:
        address = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
    except ValueError:
        return jsonify({'error': f'Bad address: {addr_str}'}), 400
    instructions = session.executor.disasm_at(address, count)
    rip = session.state.get_register('RIP')
    return jsonify({'instructions': instructions, 'current_rip': f'0x{rip:016x}'}), 200


@api.route('/resume/<session_id>', methods=['POST'])
def resume(session_id):
    """Complete a paused gets()/scanf() call with user-provided input."""
    session, err = _session_or_404(session_id)
    if err: return err
    body  = request.get_json(silent=True) or {}
    text  = body.get('input', '')
    result = session.executor.resume_from_input(text)
    result.setdefault('new_output', [])
    return jsonify(result), 200


@api.route('/restart/<session_id>', methods=['POST'])
def restart(session_id):
    """Re-run the same binary from the beginning without re-uploading."""
    session, err = _session_or_404(session_id)
    if err:
        return err
    try:
        session.restart()
    except Exception as e:
        return jsonify({'error': f'Restart failed: {e}'}), 500

    info  = session.executor.get_binary_info()
    state = session.state.get_snapshot()
    return jsonify({
        'session_id':  session_id,
        'entry_point': f'0x{info["entry_point"]:016x}',
        'state':       state,
    }), 200


@api.route('/session/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    deleted = session_manager.delete(session_id)
    return jsonify({'deleted': deleted}), 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/sessions
# ─────────────────────────────────────────────────────────────────────────────

@api.route('/sessions', methods=['GET'])
def list_sessions():
    return jsonify({'sessions': session_manager.list_sessions()}), 200
