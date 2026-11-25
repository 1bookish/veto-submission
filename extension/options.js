// Veto.ai settings. Everything is stored in this browser only (chrome.storage.local).
const KEYS = ['server', 'online', 'aiAuto', 'groqKey', 'groqModel', 'scanMessages', 'warnPages', 'lang', 'trusted'];
const DEFAULTS = { server: 'http://localhost:8787', online: true, aiAuto: true, groqKey: '', groqModel: 'qwen/qwen3.8-27b', scanMessages: true, warnPages: true, lang: 'en', trusted: [] };
const $ = id => document.getElementById(id);
let state = { ...DEFAULTS };

function renderTrusted() {
  const ul = $('trusted');
  ul.replaceChildren();
  for (const host of state.trusted) {
    const li = document.createElement('li');
    const name = document.createElement('span'); name.className = 'host'; name.textContent = host;
    const b = document.createElement('button'); b.type = 'button'; b.textContent = 'Remove';
    b.addEventListener('click', () => { state.trusted = state.trusted.filter(x => x !== host); renderTrusted(); });
    li.append(name, b);
    ul.append(li);
  }
  $('noTrusted').hidden = state.trusted.length > 0;
}

async function load() {
  try { state = { ...DEFAULTS, ...(await chrome.storage.local.get(KEYS)) }; } catch { state = { ...DEFAULTS }; }
  for (const k of ['online', 'aiAuto', 'scanMessages', 'warnPages']) $(k).checked = !!state[k];
  $('server').value = state.server; $('groqKey').value = state.groqKey; $('groqModel').value = state.groqModel; $('lang').value = state.lang;
  renderTrusted();
  chrome.runtime.sendMessage({ type: 'veto:status' }, s => {
    void chrome.runtime.lastError;
    $('serverState').textContent = !s ? '' : s.server ? `Server found${s.serverAi ? ', with an AI key' : ', no AI key on it'}.` : 'No Veto server answering at this address right now.';
  });
}

$('save').addEventListener('click', async () => {
  const next = { ...state };
  for (const k of ['online', 'aiAuto', 'scanMessages', 'warnPages']) next[k] = $(k).checked;
  next.server = ($('server').value.trim() || DEFAULTS.server).replace(/\/+$/, '');
  next.groqKey = $('groqKey').value.trim();
  next.groqModel = $('groqModel').value.trim() || DEFAULTS.groqModel;
  next.lang = $('lang').value;
  await chrome.storage.local.set(next);
  state = next;
  $('saved').textContent = 'Saved.';
  setTimeout(() => { $('saved').textContent = ''; }, 2000);
});

load();
