(() => {
  'use strict';
  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  const LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' };
  const MAX_BYTES = 512 * 1024;
  const OK_EXT = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py'];
  const $ = (id) => document.getElementById(id);

  // All page content is created with textContent, so scanned code can never inject markup.
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v; else el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null) el.append(kid);
    return el;
  }

  let clientId = '';
  try {
    clientId = localStorage.getItem('codecook-client') || '';
    if (!/^[a-f0-9-]{16,64}$/.test(clientId)) { clientId = crypto.randomUUID(); localStorage.setItem('codecook-client', clientId); }
  } catch { clientId = crypto.randomUUID(); }

  const state = { result: null, sev: null, conf: 'all' };
  const els = ['language', 'sample', 'file', 'filename', 'code', 'scan', 'clear', 'save', 'status', 'results', 'meta', 'bar', 'counts', 'conf', 'shown', 'list', 'disclaimer', 'download', 'history', 'clear-history']
    .reduce((o, id) => { o[id] = $(id); return o; }, {});

  function setStatus(msg, kind) { els.status.textContent = msg; els.status.className = 'status' + (kind ? ' ' + kind : ''); }

  /* ---------- samples ---------- */
  for (const [key, s] of Object.entries(window.SAMPLES || {})) els.sample.append(h('option', { value: key, text: s.label }));
  els.sample.addEventListener('change', () => {
    const s = window.SAMPLES[els.sample.value];
    if (!s) return;
    els.code.value = s.code; els.filename.value = s.filename; els.language.value = 'auto';
    setStatus('Example loaded. Choose "Scan code" to analyse it.');
  });

  /* ---------- file upload and drag-and-drop ---------- */
  async function loadFile(file) {
    if (!file) return;
    const ext = file.name.includes('.') ? '.' + file.name.split('.').pop().toLowerCase() : '';
    if (!OK_EXT.includes(ext)) return setStatus(`"${file.name}" is not supported. Use ${OK_EXT.join(', ')}.`, 'error');
    if (file.size > MAX_BYTES) return setStatus(`"${file.name}" is larger than ${MAX_BYTES / 1024} KB. Split it or scan a smaller file.`, 'error');
    try {
      els.code.value = await file.text();
      els.filename.value = file.name; els.language.value = 'auto'; els.sample.value = '';
      setStatus(`Loaded ${file.name}. Choose "Scan code" to analyse it.`);
    } catch { setStatus('The file could not be read. Try again or paste the code.', 'error'); }
  }
  els.file.addEventListener('change', () => { loadFile(els.file.files[0]); els.file.value = ''; });
  els.code.addEventListener('dragover', (e) => { e.preventDefault(); els.code.classList.add('drag'); });
  els.code.addEventListener('dragleave', () => els.code.classList.remove('drag'));
  els.code.addEventListener('drop', (e) => { e.preventDefault(); els.code.classList.remove('drag'); loadFile(e.dataTransfer.files[0]); });

  els.clear.addEventListener('click', () => {
    els.code.value = ''; els.filename.value = ''; els.sample.value = ''; els.results.hidden = true; state.result = null; setStatus('');
    els.code.focus();
  });

  /* ---------- scan ---------- */
  els.scan.addEventListener('click', async () => {
    const code = els.code.value;
    if (!code.trim()) return setStatus('Paste code or upload a file first.', 'error');
    els.scan.disabled = true; setStatus('Scanning…');
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Client-Id': clientId },
        body: JSON.stringify({ code, filename: els.filename.value.trim() || undefined, language: els.language.value, save: els.save.checked })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Scan failed (status ${res.status}).`);
      state.sev = null; state.conf = 'all'; els.conf.value = 'all';
      render(data);
      setStatus(data.summary.total ? `Scan complete: ${data.summary.total} finding${data.summary.total === 1 ? '' : 's'}.` : 'Scan complete: no findings from the current rules.', 'ok');
      if (data.saved) loadHistory();
      els.results.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    } catch (e) {
      setStatus(e instanceof TypeError ? 'Could not reach the CodeCook server. Check that it is running and try again.' : e.message, 'error');
    } finally { els.scan.disabled = false; }
  });

  /* ---------- results ---------- */
  function render(result) {
    state.result = result;
    els.results.hidden = false;
    const s = result.summary;
    els.meta.textContent = `${result.file} · ${result.language === 'python' ? 'Python' : 'JavaScript/TypeScript'} · ${result.lineCount} lines · ${s.confirmed} confirmed, ${s.potential} potential · scanned in ${result.durationMs} ms with ${result.scanner.ruleCount} rules`;
    els.bar.replaceChildren(...SEVS.filter((k) => s.bySeverity[k]).map((k) => { const sp = h('span'); sp.style.width = (s.bySeverity[k] / s.total * 100) + '%'; sp.style.background = `var(--${k})`; return sp; }));
    els.counts.replaceChildren(...SEVS.map((k) => {
      const b = h('button', { type: 'button', class: `count sev-${k}`, 'aria-pressed': String(state.sev === k) }, h('b', { text: String(s.bySeverity[k]) }), LABEL[k]);
      b.style.borderTopColor = `var(--${k})`;
      b.addEventListener('click', () => { state.sev = state.sev === k ? null : k; render(state.result); });
      return b;
    }));
    els.disclaimer.textContent = result.disclaimer;
    if (result.truncatedLines) els.disclaimer.textContent += ` ${result.truncatedLines} very long line(s) were only partly analysed.`;
    renderList();
  }

  function renderList() {
    const r = state.result;
    const items = r.findings.filter((f) => (!state.sev || f.severity === state.sev) && (state.conf === 'all' || f.confidence === state.conf));
    els.shown.textContent = r.findings.length ? `Showing ${items.length} of ${r.findings.length}` : '';
    if (!items.length) {
      els.list.replaceChildren(h('div', { class: 'empty' }, h('p', { text: r.findings.length ? 'No findings match these filters.' : 'No findings from the current rules.' }), h('p', { text: r.findings.length ? 'Clear a filter to see the rest.' : 'This does not prove the code is secure: CodeCook covers common JavaScript/TypeScript and Python patterns only.' })));
      return;
    }
    els.list.replaceChildren(...items.map(findingCard));
  }
  els.conf.addEventListener('change', () => { state.conf = els.conf.value; if (state.result) renderList(); });

  function section(title, text) { return [h('h3', { text: title }), h('p', { text })]; }

  function findingCard(f) {
    const code = h('pre', {}, f.snippet.map((l) => h('span', { class: 'ln' + (l.hit ? ' hit' : '') }, h('i', { text: String(l.n) }), l.text)));
    const secure = h('pre', { text: f.fix.secureExample });
    const copy = h('button', { type: 'button', class: 'btn ghost small', text: 'Copy fix' });
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(f.fix.secureExample); }
      catch { const t = h('textarea', {}); t.value = f.fix.secureExample; document.body.append(t); t.select(); document.execCommand('copy'); t.remove(); }
      copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = 'Copy fix'; }, 1500);
    });
    return h('details', { class: `finding sev-${f.severity}` },
      h('summary', {},
        h('span', { class: 'badge solid', text: LABEL[f.severity] }),
        h('span', { class: 'f-title', text: f.title }),
        h('span', { class: 'badge', text: f.confidence === 'confirmed' ? 'Confirmed pattern' : 'Potential, review' }),
        h('span', { class: 'f-loc', text: `${f.file}:${f.line}` })),
      h('div', { class: 'f-body' },
        h('p', { class: 'rule-id', text: `${f.ruleId} · ${f.cwe}` }),
        h('h3', { text: 'Evidence' }), code,
        ...section('Why this severity', f.severityReason),
        h('h3', {}, 'Explanation ', h('span', { class: 'label', text: 'Rule-based text, not AI' })),
        ...section('What the problem is', f.explanation.what),
        ...section('Why it matters', f.explanation.whyItMatters),
        ...section('How an attacker might abuse it (safe example)', f.explanation.attackExample),
        ...section('What must be true for it to be exploitable', f.explanation.conditions),
        ...section('How to fix it', f.explanation.howToFix),
        h('div', { class: 'compare' },
          h('div', {}, h('h3', { text: 'Your code' }), code.cloneNode(true)),
          h('div', {}, h('h3', { text: 'Safer version' }), secure, copy)),
        f.fix.notes.length ? h('ul', { class: 'notes' }, f.fix.notes.map((n) => h('li', { text: n }))) : null,
        h('p', { class: 'hint', text: f.fix.note })));
  }

  els.download.addEventListener('click', () => {
    if (!state.result) return;
    const blob = new Blob([JSON.stringify(state.result, null, 2)], { type: 'application/json' });
    const a = h('a', { href: URL.createObjectURL(blob), download: `codecook-report-${state.result.file.replace(/[^\w.-]/g, '_')}.json` });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  /* ---------- history ---------- */
  const api = (path, opts = {}) => fetch(path, { ...opts, headers: { 'X-Client-Id': clientId, ...(opts.headers || {}) } });

  async function loadHistory() {
    try {
      const res = await api('/api/history');
      const items = res.ok ? await res.json() : [];
      els.history.replaceChildren(...(items.length ? items.map(historyRow) : [h('li', { class: 'hint', text: 'No saved scans yet. Tick "Save results to history" before scanning.' })]));
    } catch { els.history.replaceChildren(h('li', { class: 'hint', text: 'History is unavailable right now.' })); }
  }
  function historyRow(it) {
    const open = h('button', { type: 'button', class: 'btn ghost small', text: 'Open' });
    const del = h('button', { type: 'button', class: 'btn ghost small', text: 'Delete' });
    open.addEventListener('click', async () => {
      const res = await api('/api/history/' + encodeURIComponent(it.scanId));
      if (!res.ok) return setStatus('That saved scan no longer exists.', 'error');
      state.sev = null; state.conf = 'all'; els.conf.value = 'all'; render(await res.json());
      els.results.scrollIntoView({ block: 'start' });
    });
    del.addEventListener('click', async () => { await api('/api/history/' + encodeURIComponent(it.scanId), { method: 'DELETE' }); loadHistory(); });
    return h('li', {}, h('div', {}, h('strong', { text: it.file }), h('div', { class: 'meta', text: `${new Date(it.savedAt).toLocaleString()} · ${it.summary.total} findings` })), h('div', {}, open, ' ', del));
  }
  els['clear-history'].addEventListener('click', async () => {
    if (!confirm('Delete all saved scans for this browser?')) return;
    await api('/api/history', { method: 'DELETE' }); loadHistory();
  });
  loadHistory();
})();
