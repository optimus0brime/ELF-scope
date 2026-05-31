/**
 * ui.js — application controller (WinDbg layout, pause-on-input, args, restart).
 */

// ── State ──────────────────────────────────────────────────────
let _isRunning       = false;
let _runInterval     = null;
let _isStepping      = false;
let _runStepCount    = 0;
let _activeTab       = 'memory';
let _waitingForInput = false;   // paused at gets()/scanf()
let _resumeAfterInput= false;   // whether to restart Run after input is sent

// ── DOM refs ───────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const dom = {
  uploadPanel:  $('upload-panel'),
  dashboard:    $('dashboard'),
  fileInput:    $('file-input'),
  browseBtn:    $('browse-btn'),
  uploadBox:    $('upload-box'),
  uploadError:  $('upload-error'),
  argsInput:    $('args-input'),

  btnStep:     $('btn-step'),   btnRun:     $('btn-run'),
  btnPause:    $('btn-pause'),  btnRestart: $('btn-restart'),
  btnNewBin:   $('btn-newbin'),

  btnMemFetch: $('btn-mem-fetch'),
  memAddr:     $('mem-addr'),
  memSize:     $('mem-size'),

  statusBadge: $('status-badge'),
  chipFile:    $('chip-filename'),
  chipEntry:   $('chip-entry'),
  chipCount:   $('chip-instr-count'),
  ctrlArgsVal: $('ctrl-args-val'),

  haltBanner:     $('halt-banner'),
  haltBannerIcon: $('halt-banner-icon'),
  haltBannerMsg:  $('halt-banner-msg'),

  waitBanner:  $('wait-input-banner'),
  waitMsg:     $('wait-input-msg'),
  termInput:   $('term-input'),
  termOutput:  $('term-output'),

  logDot:      $('log-dot'),
};

// ── Tab switching ──────────────────────────────────────────────
function switchTab(name) {
  _activeTab = name;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab===name));
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.toggle('hidden', p.id !== `tab-${name}`);
    p.classList.toggle('active', p.id === `tab-${name}`);
  });
  if (name === 'log') dom.logDot.classList.add('hidden');
}

function _bumpLogDot(level) {
  if (_activeTab !== 'log' && (level==='error'||level==='warn'))
    dom.logDot.classList.remove('hidden');
}

// ── Status helpers ─────────────────────────────────────────────
function setStatus(text, cls) {
  dom.statusBadge.textContent = text;
  dom.statusBadge.className   = `status-badge ${cls||''}`;
}
function setCount(n) { dom.chipCount.textContent = `${n} instrs`; }

// ── Halt banner ────────────────────────────────────────────────
function showHaltBanner(msg, isError) {
  dom.haltBanner.className = `halt-banner ${isError?'error':'done'}`;
  dom.haltBannerIcon.textContent = isError ? '🛑' : '✅';
  dom.haltBannerMsg.textContent  = msg;
  dom.haltBanner.classList.remove('hidden');
}
function hideHaltBanner() { dom.haltBanner.classList.add('hidden'); }

// ── Wait-for-input state ───────────────────────────────────────
function enterWaitMode(funcName) {
  _waitingForInput = true;
  dom.waitBanner.classList.remove('hidden');
  dom.waitMsg.textContent = `Program paused — ${funcName||'input function'}() is waiting for input`;
  dom.termInput.classList.add('waiting');
  dom.termInput.focus();
  _stopRun();
  setStatus('INPUT', 'loaded');
  _setButtons('input');
  termWrite(`\n[${funcName||'stdin'}] waiting for input...\n`, 'system');
}

function exitWaitMode() {
  _waitingForInput = false;
  dom.waitBanner.classList.add('hidden');
  dom.termInput.classList.remove('waiting');
}

// ── Upload ─────────────────────────────────────────────────────
async function handleFileSelected(file) {
  dom.uploadError.textContent = '';
  setStatus('LOADING…', '');
  const args = dom.argsInput?.value.trim() || '';

  try {
    const data = await apiExecute(file, args);

    dom.chipFile.textContent  = file.name;
    dom.chipEntry.textContent = data.entry_point;
    dom.ctrlArgsVal.textContent = args || '—';
    setCount(0);

    initRegisters();
    initFlags();
    renderState(data.state);

    // Show disasm at entry point
    dom.memAddr.value = data.entry_point;
    await refreshDisasm(data.entry_point);

    dom.uploadPanel.classList.add('hidden');
    dom.dashboard.classList.remove('hidden');
    setStatus('LOADED', 'loaded');
    _setButtons('ready');
    hideHaltBanner();
    switchTab('memory');

    log.system(`Loaded ${file.name}`, `session ${getSessionId().slice(0,8)}…`);
    log.info(`Entry: ${data.entry_point}`);
    const ts = (data.sections||[]).find(s=>s.name==='.text');
    if (ts) log.info(`.text @ 0x${ts.address.toString(16).padStart(16,'0')}`, `${ts.size}B`);
    const fns = (data.symbols||[]).filter(s=>s.type==='STT_FUNC').slice(0,6);
    fns.forEach(s => log.info(`fn: ${s.name}`, `0x${s.address.toString(16).padStart(16,'0')}`));
    if (!fns.length) log.warn('No symbols found','binary may be stripped');
    if (args) log.info(`argv`, args);
    log.info('Ready');

  } catch(err) {
    dom.uploadError.textContent = `Error: ${err.message}`;
    setStatus('ERROR','');
    log.error('Load failed', err.message);
    _bumpLogDot('error');
  }
}

// ── Disasm refresh ─────────────────────────────────────────────
async function refreshDisasm(ripOrAddr) {
  const addr = ripOrAddr || document.getElementById('disasm-rip')?.textContent?.replace('RIP: ','') || '0x0';
  try {
    const data = await apiDisasm(addr, 30);
    renderDisasm(data.instructions, data.current_rip);
  } catch(e) { /* ignore */ }
}

// ── Step ───────────────────────────────────────────────────────
async function doStep() {
  if (_isStepping || _waitingForInput) return;
  _isStepping = true;

  try {
    const r = await apiStep();

    // ── Waiting for input ──────────────────────────────────
    if (r.waiting_for_input) {
      if (r.instruction) renderStep(r);
      (r.new_output||[]).forEach(l => termWrite(l,'stdout'));
      if (r.stub_log) { termWrite(r.stub_log,'stub'); log.info(r.stub_log); }
      _resumeAfterInput = _isRunning;
      enterWaitMode(r.pending_func);
      return;
    }

    // ── Halt ───────────────────────────────────────────────
    if (r.halted || r.error) {
      const reason  = r.halt_reason || r.error || 'Halted';
      const isError = _isHaltError(reason);
      if (r.instruction) renderStep(r);
      (r.new_output||[]).forEach(l => termWrite(l,'stdout'));
      if (r.stub_log) termWrite(r.stub_log,'stub');
      showHaltBanner(reason, isError);
      isError ? log.error('Halted', reason) : log.system('Done', reason);
      if (isError) _bumpLogDot('error');
      termWrite(`\n[${isError?'HALT':'DONE'}] ${reason}\n`,'system');
      _handleHalt(isError);
      return;
    }

    // ── Normal step ────────────────────────────────────────
    renderStep(r);
    setCount(r.state_after.instruction_count);
    (r.new_output||[]).forEach(l => termWrite(l,'stdout'));
    if (r.stub_log) { termWrite(r.stub_log,'stub'); log.info(r.stub_log); }
    log.step(r.instruction, r.changed_registers, r.changed_flags);

    // Refresh disasm around new RIP
    const rip = r.state_after?.registers?.RIP;
    if (rip) refreshDisasm(`0x${BigInt(rip).toString(16)}`);

    if (_isRunning) _runStepCount++;

  } catch(err) {
    _stopRun();
    setStatus('ERROR','');
    log.error('Step error', err.message);
    _bumpLogDot('error');
  } finally {
    _isStepping = false;
  }
}

// ── Run / Pause ────────────────────────────────────────────────
function startRun() {
  if (_isRunning || _waitingForInput) return;
  _isRunning = true; _runStepCount = 0;
  setStatus('RUNNING','running');
  _setButtons('running');
  log.setStepVerbose(false);
  log.system('Run started');
  _runInterval = setInterval(async () => { await doStep(); }, RUN_INTERVAL_MS);
}

function _stopRun() {
  if (_runInterval) { clearInterval(_runInterval); _runInterval = null; }
  _isRunning = false;
  log.setStepVerbose(true);
}

function pauseRun() {
  _stopRun();
  log.stepSummary(_runStepCount, document.getElementById('disasm-rip')?.textContent||'');
  log.system('Paused');
  setStatus('PAUSED','loaded');
  _setButtons('ready');
}

// ── Stdin send (also used as "Resume" when waiting_for_input) ──
async function handleStdinSend() {
  const text = dom.termInput?.value.trim();
  if (!text || !getSessionId()) return;

  if (_waitingForInput) {
    // Resume the paused input function
    dom.termInput.value = '';
    exitWaitMode();
    termWrite(`stdin> ${text}\n`, 'system');
    try {
      const r = await apiResume(text);
      (r.new_output||[]).forEach(l => termWrite(l,'stdout'));
      if (r.instruction) renderStep(r);
      if (r.state_after) setCount(r.state_after.instruction_count);
      const rip = r.state_after?.registers?.RIP;
      if (rip) refreshDisasm(`0x${BigInt(rip).toString(16)}`);
      log.info(`resumed ${r.instruction?.mnemonic||''}`, text.slice(0,30));

      // If we were running before the pause, resume running
      if (_resumeAfterInput) {
        _resumeAfterInput = false;
        setStatus('RUNNING','running');
        _setButtons('running');
        log.setStepVerbose(false);
        _isRunning = true;
        _runInterval = setInterval(async () => { await doStep(); }, RUN_INTERVAL_MS);
      } else {
        setStatus('LOADED','loaded');
        _setButtons('ready');
      }
    } catch(err) {
      log.error('Resume failed', err.message);
      _bumpLogDot('error');
      setStatus('ERROR','');
    }
    return;
  }

  // Normal stdin queue
  try {
    const result = await apiSendStdin(text);
    termWrite(`stdin> ${text}\n`, 'system');
    const badge = $('stdin-count');
    if (badge) badge.textContent = `${result.queued} queued`;
    log.info(`stdin: "${text}"`, `${result.queued} queued`);
    dom.termInput.value = '';
  } catch(err) {
    log.error('stdin failed', err.message);
    _bumpLogDot('error');
  }
}

// ── Halt ───────────────────────────────────────────────────────
function _handleHalt(isError) {
  _stopRun();
  setStatus(isError?'ERROR':'DONE', isError?'halted':'loaded');
  _setButtons('halted');
}

function _isHaltError(r) {
  if (!r) return false;
  const s = r.toLowerCase();
  return !s.includes('returned') && !s.includes('exit(') && !s.includes('normally');
}

// ── Restart ────────────────────────────────────────────────────
async function restartSession() {
  _stopRun(); exitWaitMode(); hideHaltBanner();
  try {
    const data = await apiRestart();
    setStatus('LOADED','loaded');
    setCount(0);
    _setButtons('ready');
    renderState(data.state);
    $('disasm-body').innerHTML = '<div class="disasm-placeholder dim">Restarted — Step to begin</div>';
    $('history-list').innerHTML = '';
    $('history-count').textContent = '0';
    renderCallStack([]);
    termClear();
    await refreshDisasm(data.entry_point);
    log.system('Restarted', data.entry_point);
    switchTab('memory');
  } catch(err) {
    log.error('Restart failed', err.message);
    _bumpLogDot('error');
  }
}

// ── New binary ─────────────────────────────────────────────────
async function loadNewBinary() {
  _stopRun(); exitWaitMode();
  try { await apiDeleteSession(); } catch(_) {}
  dom.dashboard.classList.add('hidden');
  dom.uploadPanel.classList.remove('hidden');
  dom.uploadError.textContent = '';
  dom.chipFile.textContent = 'no binary';
  dom.chipEntry.textContent = '';
  setCount(0); setStatus('IDLE','');
  hideHaltBanner(); termClear(); log.clear();
}

// ── Terminal ───────────────────────────────────────────────────
function termWrite(text, type='stdout') {
  const el = $('term-output');
  if (!el) return;
  const ph = el.querySelector('.term-placeholder');
  if (ph) el.removeChild(ph);
  const sp = document.createElement('span');
  sp.className = `term-line ${type}`;
  sp.textContent = text;
  el.appendChild(sp);
  el.scrollTop = el.scrollHeight;
}
function termClear() {
  const el = $('term-output');
  if (el) el.innerHTML = '<span class="term-placeholder">Terminal cleared.</span>';
}

// ── Memory ─────────────────────────────────────────────────────
async function fetchMemory() {
  const addr = dom.memAddr?.value.trim() || '0x400000';
  const size = parseInt(dom.memSize?.value.trim() || '64');
  try {
    const data = await apiGetMemory(addr, size);
    renderMemory(data);
    log.info('Memory', `${addr} ${size}B`);
  } catch(err) {
    log.error('Memory read failed', `${addr} — ${err.message}`);
    _bumpLogDot('error');
  }
}

// ── Button state ───────────────────────────────────────────────
function _setButtons(state) {
  const {btnStep:s,btnRun:r,btnPause:p,btnRestart:rs} = dom;
  const map = {
    ready:   [false,false,true, false],
    running: [true, true, false,true ],
    halted:  [true, true, true, false],
    input:   [true, true, true, false],
  };
  const [sd,rd,pd,rsd] = map[state] || map.ready;
  s.disabled=sd; r.disabled=rd; p.disabled=pd; rs.disabled=rsd;
}

// ── Event listeners ────────────────────────────────────────────
dom.browseBtn.addEventListener('click', () => dom.fileInput.click());
dom.fileInput.addEventListener('change', e => { if(e.target.files[0]) handleFileSelected(e.target.files[0]); });
dom.uploadBox.addEventListener('click',   e => { if(e.target!==dom.browseBtn && !dom.argsInput?.contains(e.target)) dom.fileInput.click(); });
dom.uploadBox.addEventListener('dragover',  e => { e.preventDefault(); dom.uploadBox.classList.add('drag-over'); });
dom.uploadBox.addEventListener('dragleave', () => dom.uploadBox.classList.remove('drag-over'));
dom.uploadBox.addEventListener('drop', e => {
  e.preventDefault(); dom.uploadBox.classList.remove('drag-over');
  if(e.dataTransfer.files[0]) handleFileSelected(e.dataTransfer.files[0]);
});

dom.btnStep.addEventListener('click',    () => doStep());
dom.btnRun.addEventListener('click',     () => startRun());
dom.btnPause.addEventListener('click',   () => pauseRun());
dom.btnRestart.addEventListener('click', () => restartSession());
dom.btnNewBin.addEventListener('click',  () => loadNewBinary());

$('btn-term-send')?.addEventListener('click', handleStdinSend);
$('term-input')?.addEventListener('keydown', e => { if(e.key==='Enter') handleStdinSend(); });
$('btn-term-clear')?.addEventListener('click', termClear);

dom.btnMemFetch?.addEventListener('click', fetchMemory);
dom.memAddr?.addEventListener('keydown', e => { if(e.key==='Enter') fetchMemory(); });

document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));

$('btn-log-clear')?.addEventListener('click', () => { if(typeof log!=='undefined') log.clear(); });

document.addEventListener('keydown', e => {
  if(dom.dashboard.classList.contains('hidden')) return;
  if(e.target.tagName==='INPUT') return;
  if(e.key==='n'||e.key==='s') doStep();
  if(e.key==='r'&&!e.shiftKey) startRun();
  if(e.key==='p') pauseRun();
  if(e.key==='R'||e.key==='r'&&e.shiftKey) restartSession();
});
