// API_BASE is defined in constants.js
let _sid = null;
const getSessionId  = () => _sid;
const setSessionId  = id => { _sid = id; };
const clearSessionId = () => { _sid = null; };

async function _req(method, path, body=null, isFile=false) {
  const opts = { method, headers: isFile ? {} : {'Content-Type':'application/json'} };
  if (body !== null) opts.body = isFile ? body : JSON.stringify(body);
  const res  = await fetch(`${API_BASE}${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiExecute(file, args='') {
  const form = new FormData();
  form.append('file', file);
  if (args) form.append('args', args);
  const data = await _req('POST', '/execute', form, true);
  setSessionId(data.session_id);
  return data;
}
async function apiStep()               { if(!_sid)throw new Error('no session'); return _req('POST',`/step/${_sid}`); }
async function apiGetState()           { if(!_sid)throw new Error('no session'); return _req('GET',`/state/${_sid}`); }
async function apiGetMemory(addr,size=64){ if(!_sid)throw new Error('no session'); return _req('GET',`/memory/${_sid}?address=${addr}&size=${size}`); }
async function apiSetRegister(reg,val) { if(!_sid)throw new Error('no session'); return _req('POST',`/register/${_sid}`,{register:reg,value:val}); }
async function apiSendStdin(text)      { if(!_sid)throw new Error('no session'); return _req('POST',`/stdin/${_sid}`,{text}); }
async function apiGetStdout(flush=false){ if(!_sid)throw new Error('no session'); return _req('GET',`/stdout/${_sid}?flush=${flush?1:0}`); }
async function apiGetHistory(limit=100){ if(!_sid)throw new Error('no session'); return _req('GET',`/history/${_sid}?limit=${limit}`); }
async function apiDisasm(addr,count=30){ if(!_sid)throw new Error('no session'); return _req('GET',`/disasm/${_sid}?address=${addr}&count=${count}`); }
async function apiResume(input)        { if(!_sid)throw new Error('no session'); return _req('POST',`/resume/${_sid}`,{input}); }
async function apiRestart()            { if(!_sid)throw new Error('no session'); return _req('POST',`/restart/${_sid}`); }
async function apiDeleteSession()      { if(!_sid)return; await _req('DELETE',`/session/${_sid}`); clearSessionId(); }
