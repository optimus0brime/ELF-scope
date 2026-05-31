/**
 * logger.js — execution log panel.
 *
 * Every meaningful event during emulation gets a timestamped, color-coded
 * entry here: binary loads, each executed instruction, register changes,
 * syscall stubs, memory faults, API errors, halts, and user actions.
 *
 * Log levels:
 *   info   — normal events (instructions executed, binary loaded)
 *   warn   — recoverable issues (syscall stubbed, memory read of unmapped region)
 *   error  — hard failures (Unicorn error, bad ELF, network failure)
 *   system — lifecycle events (session created/reset, paused/resumed)
 *   step   — per-instruction trace lines (suppressed in Run mode to avoid spam)
 *
 * Public API (called from ui.js):
 *   log.info(msg, detail?)
 *   log.warn(msg, detail?)
 *   log.error(msg, detail?)
 *   log.system(msg, detail?)
 *   log.step(instr, changedRegs, changedFlags)
 *   log.clear()
 *   log.setStepVerbose(bool)   — suppress step lines during Run mode
 */

const log = (() => {

  // ── Internal state ──────────────────────────────────────────
  let _entries       = [];      // all log entries ever added this session
  let _stepVerbose   = true;    // false while running continuously
  let _filterInfo    = true;
  let _filterWarn    = true;
  let _filterError   = true;
  let _placeholder   = null;    // the "Waiting…" div, removed on first entry
  let _domReady      = false;

  // ── DOM references ──────────────────────────────────────────
  let _body, _chkInfo, _chkWarn, _chkError, _btnClear;

  function _init() {
    _body     = document.getElementById('log-body');
    _chkInfo  = document.getElementById('log-filter-info');
    _chkWarn  = document.getElementById('log-filter-warn');
    _chkError = document.getElementById('log-filter-error');
    _btnClear = document.getElementById('btn-log-clear');

    _placeholder = _body.querySelector('.log-placeholder');

    _chkInfo.addEventListener('change',  () => { _filterInfo  = _chkInfo.checked;  _rerender(); });
    _chkWarn.addEventListener('change',  () => { _filterWarn  = _chkWarn.checked;  _rerender(); });
    _chkError.addEventListener('change', () => { _filterError = _chkError.checked; _rerender(); });
    _btnClear.addEventListener('click',  () => clear());

    _domReady = true;
  }

  // ── Core append ─────────────────────────────────────────────

  function _append(level, msg, detail) {
    const entry = { level, msg, detail: detail || null, time: _timestamp() };
    _entries.push(entry);

    // Notify ui.js so it can light up the Log tab badge
    if (typeof _bumpLogBadge === 'function') _bumpLogBadge(level);

    if (_domReady && _shouldShow(level)) {
      _removePlaceholder();
      _body.appendChild(_makeRow(entry));
      _scrollToBottom();
    }
  }

  function _shouldShow(level) {
    if (level === 'info'   && !_filterInfo)  return false;
    if (level === 'warn'   && !_filterWarn)  return false;
    if (level === 'error'  && !_filterError) return false;
    return true;
  }

  function _rerender() {
    if (!_domReady) return;
    _body.innerHTML = '';
    _placeholder = null;

    const visible = _entries.filter(e => _shouldShow(e.level));
    if (visible.length === 0) {
      const p = document.createElement('div');
      p.className = 'log-placeholder';
      p.textContent = 'No entries match current filters.';
      _body.appendChild(p);
      _placeholder = p;
      return;
    }
    visible.forEach(e => _body.appendChild(_makeRow(e)));
    _scrollToBottom();
  }

  // ── Row construction ─────────────────────────────────────────

  function _makeRow(entry) {
    const row = document.createElement('div');
    row.className = `log-entry log-${entry.level}`;

    const time   = document.createElement('span');
    time.className = 'log-time';
    time.textContent = entry.time;

    const badge  = document.createElement('span');
    badge.className = `log-badge log-badge-${entry.level}`;
    badge.textContent = entry.level.toUpperCase();

    const text   = document.createElement('span');
    text.className = 'log-msg';
    text.textContent = entry.msg;

    row.appendChild(time);
    row.appendChild(badge);
    row.appendChild(text);

    if (entry.detail) {
      const detail = document.createElement('span');
      detail.className = 'log-detail';
      detail.textContent = entry.detail;
      row.appendChild(detail);
    }

    return row;
  }

  // ── Helpers ──────────────────────────────────────────────────

  function _timestamp() {
    const d = new Date();
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${hh}:${mm}:${ss}.${ms}`;
  }

  function _removePlaceholder() {
    if (_placeholder && _placeholder.parentNode === _body) {
      _body.removeChild(_placeholder);
      _placeholder = null;
    }
  }

  function _scrollToBottom() {
    _body.scrollTop = _body.scrollHeight;
  }

  // ── Public API ───────────────────────────────────────────────

  function info(msg, detail)   { _append('info',   msg, detail); }
  function warn(msg, detail)   { _append('warn',   msg, detail); }
  function error(msg, detail)  { _append('error',  msg, detail); }
  function system(msg, detail) { _append('system', msg, detail); }

  /**
   * step — log a single instruction execution.
   *
   * Suppressed (not logged) when _stepVerbose is false (during Run mode)
   * because at 80ms/instruction it would generate ~750 entries/minute.
   * In Run mode we instead log a summary when paused/halted.
   *
   * Format:  0x0000000000401000  push rbp          Δ RSP, RIP
   */
  function step(instr, changedRegs, changedFlags) {
    if (!_stepVerbose) return;

    const delta = [
      ...(changedRegs  || []).map(r => r.register),
      ...(changedFlags || []).map(f => `${f.flag}=${f.after}`),
    ].join(', ');

    const msg    = `${instr.address}  ${instr.mnemonic.padEnd(8)} ${instr.op_str}`;
    const detail = delta ? `Δ ${delta}` : '';
    _append('step', msg, detail);
  }

  /**
   * stepSummary — called after pausing/halting in Run mode.
   * Shows how many instructions ran and what the final RIP is.
   */
  function stepSummary(count, finalRip) {
    _append('info',
      `Run mode: executed ${count} instructions`,
      `stopped at ${finalRip}`
    );
  }

  function clear() {
    _entries = [];
    if (!_domReady) return;
    _body.innerHTML = '';
    const p = document.createElement('div');
    p.className = 'log-placeholder';
    p.textContent = 'Log cleared.';
    _body.appendChild(p);
    _placeholder = p;
  }

  function setStepVerbose(v) { _stepVerbose = v; }

  // Initialise once the DOM is ready
  document.addEventListener('DOMContentLoaded', _init);
  // If DOMContentLoaded already fired (script loaded late), init immediately
  if (document.readyState !== 'loading') {
    setTimeout(_init, 0);
  }

  return { info, warn, error, system, step, stepSummary, clear, setStepVerbose };

})();
