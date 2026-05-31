/**
 * state_renderer.js — DOM updates for registers, flags, memory, call stack, history.
 * Adapted for WinDbg layout: tight tables, yellow-on-change.
 */

function initRegisters() {
  const tbody = document.getElementById('reg-tbody');
  tbody.innerHTML = '';
  for (const reg of REGISTERS) {
    const tr = document.createElement('tr');
    tr.id = `reg-row-${reg}`;
    tr.innerHTML = `<td class="rn">${reg}</td>
                    <td class="rv" id="reg-val-${reg}">0x0000000000000000</td>
                    <td class="rd" id="reg-dec-${reg}">0</td>`;
    tbody.appendChild(tr);
  }
}

function initFlags() {
  const row = document.getElementById('flags-row');
  row.innerHTML = '';
  for (const f of FLAGS) {
    const chip = document.createElement('div');
    chip.className = 'flag-chip';
    chip.id = `flag-chip-${f}`;
    chip.title = FLAG_DESCRIPTIONS[f];
    chip.innerHTML = `<span class="flag-name">${f}</span><span class="flag-value" id="flag-val-${f}">0</span>`;
    row.appendChild(chip);
  }
}

/* ── After each step ───────────────────────────────────────── */

function renderStep(result) {
  if (!result || (!result.success && !result.instruction)) return;
  const { instruction, state_after, changed_registers, changed_flags } = result;
  if (instruction) _renderInstr(instruction);
  if (state_after) {
    const changedRegs  = new Set((changed_registers  || []).map(r => r.register));
    const changedFlags = new Set((changed_flags || []).map(f => f.flag));
    _updateRegisters(state_after.registers, changedRegs);
    _updateFlags(state_after.flags, changedFlags);
    renderCallStack(state_after.call_stack || []);
    _updateRflags(state_after.flags);
  }
  if (instruction) _appendHistory(instruction, (state_after || {}).instruction_count || 0);
}

function renderState(state) {
  _updateRegisters(state.registers, new Set());
  _updateFlags(state.flags, new Set());
  renderCallStack(state.call_stack || []);
  _updateRflags(state.flags);
}

/* ── Disassembly context pane ──────────────────────────────── */

const CALL_RET  = new Set(['call','ret','retn','retf','iret']);
const JMP_MNEMS = new Set(['jmp','je','jne','jz','jnz','jl','jle','jg','jge','ja','jb','jae','jbe','js','jns','jo','jno','jp','jnp','jcxz','jecxz','jrcxz','loop','loope','loopne']);
const NOP_MNEMS = new Set(['nop','endbr64','endbr32']);

function renderDisasm(instructions, currentRip) {
  const body = document.getElementById('disasm-body');
  const ripEl = document.getElementById('disasm-rip');
  body.innerHTML = '';

  if (!instructions || instructions.length === 0) {
    body.innerHTML = '<div class="disasm-placeholder dim">No instructions to display</div>';
    return;
  }

  // Update RIP indicator
  if (ripEl) ripEl.textContent = `RIP: ${currentRip || '—'}`;

  let scrollTarget = null;

  for (const ins of instructions) {
    const isCurrent = ins.address === currentRip;
    const m = ins.mnemonic.toLowerCase();

    // Mnemonic class
    let mc = '';
    if (CALL_RET.has(m))  mc = 'mc-call';
    else if (JMP_MNEMS.has(m)) mc = 'mc-jmp';
    else if (NOP_MNEMS.has(m)) mc = 'mc-nop';

    const row = document.createElement('div');
    row.className = `di${isCurrent ? ' current' : ''}`;
    row.dataset.addr = ins.address;

    // Format bytes — show up to 6 bytes then ellipsis
    const byteStr = ins.bytes
      ? (ins.bytes.length > 12 ? ins.bytes.slice(0,12)+'…' : ins.bytes).replace(/../g, h => h+' ').trim()
      : '';

    row.innerHTML =
      `<span class="di-addr">${isCurrent ? '►' : ' '} ${ins.address}</span>` +
      `<span class="di-bytes">${byteStr}</span>` +
      `<span class="di-mnem ${mc}">${ins.mnemonic}</span>` +
      `<span class="di-ops">${_escHtml(ins.op_str)}</span>`;

    body.appendChild(row);
    if (isCurrent) scrollTarget = row;
  }

  // Scroll current instruction into view (centered)
  if (scrollTarget) {
    scrollTarget.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
}

/* ── Internal helpers ──────────────────────────────────────── */

function _renderInstr(instr) {
  // The disasm pane handles context; just update RIP chip
  const ripEl = document.getElementById('disasm-rip');
  if (ripEl) ripEl.textContent = `RIP: ${instr.address}`;
}

function _updateRegisters(registers, changedSet) {
  for (const reg of REGISTERS) {
    const val   = registers[reg] ?? 0;
    const valEl = document.getElementById(`reg-val-${reg}`);
    const decEl = document.getElementById(`reg-dec-${reg}`);
    const rowEl = document.getElementById(`reg-row-${reg}`);
    if (!valEl) continue;

    valEl.textContent = `0x${BigInt(val).toString(16).padStart(16,'0')}`;
    decEl.textContent = val.toLocaleString();

    if (changedSet.has(reg)) {
      rowEl.classList.remove('reg-changed');
      void rowEl.offsetWidth;
      rowEl.classList.add('reg-changed');
    }
  }
}

function _updateFlags(flags, changedSet) {
  for (const f of FLAGS) {
    const v     = flags[f] ?? 0;
    const chip  = document.getElementById(`flag-chip-${f}`);
    const valEl = document.getElementById(`flag-val-${f}`);
    if (!chip) continue;
    valEl.textContent = v;
    chip.classList.toggle('flag-set', v === 1);
    if (changedSet.has(f)) {
      chip.classList.remove('flag-changed');
      void chip.offsetWidth;
      chip.classList.add('flag-changed');
    }
  }
}

function _updateRflags(flags) {
  const el = document.getElementById('rflags-val');
  if (!el || !flags) return;
  el.textContent = `CF=${flags.CF||0} ZF=${flags.ZF||0} SF=${flags.SF||0} OF=${flags.OF||0}`;
}

/* ── Memory hexdump ────────────────────────────────────────── */

function renderMemory(data) {
  const el = document.getElementById('hexdump');
  el.innerHTML = '';
  if (!data.rows || !data.rows.length) {
    el.innerHTML = '<span class="dim">no data</span>'; return;
  }
  for (const row of data.rows) {
    const d = document.createElement('div');
    d.className = 'hex-row';
    d.innerHTML = `<span class="hex-addr">${row.address}</span>`+
                  `<span class="hex-bytes">${row.hex}</span>`+
                  `<span class="hex-ascii">${row.ascii}</span>`;
    el.appendChild(d);
  }
}

/* ── Call stack ────────────────────────────────────────────── */

function renderCallStack(stack) {
  const el = document.getElementById('callstack');
  if (!stack || !stack.length) {
    el.innerHTML = '<span class="dim">empty</span>'; return;
  }
  el.innerHTML = '';
  [...stack].reverse().forEach((f, i) => {
    const d = document.createElement('div');
    d.className = 'cs-entry';
    d.innerHTML = `<span class="cs-depth">#${stack.length-i}</span>`+
                  `<span class="cs-site">from 0x${f.call_site.toString(16).padStart(8,'0')}</span>`+
                  `<span class="cs-target">→ 0x${f.target.toString(16).padStart(8,'0')}</span>`;
    el.appendChild(d);
  });
}

/* ── Instruction history ───────────────────────────────────── */

function _appendHistory(instr, count) {
  const list  = document.getElementById('history-list');
  const badge = document.getElementById('history-count');
  list.querySelectorAll('.current').forEach(e => e.classList.remove('current'));
  const d = document.createElement('div');
  d.className = 'history-entry current';
  d.innerHTML = `<span class="h-addr">${instr.address}</span>`+
                `<span class="h-mnem">${instr.mnemonic}</span>`+
                `<span class="h-ops">${_escHtml(instr.op_str)}</span>`;
  list.insertBefore(d, list.firstChild);
  if (badge) badge.textContent = count;
}

function _escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
