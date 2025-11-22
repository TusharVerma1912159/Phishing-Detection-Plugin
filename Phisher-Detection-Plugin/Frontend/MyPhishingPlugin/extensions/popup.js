document.addEventListener('DOMContentLoaded', () => {
  const urlInput   = document.getElementById('urlInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const currentBtn = document.getElementById('currentBtn');
  const spinner    = analyzeBtn.querySelector('.spinner');
  const btnText    = analyzeBtn.querySelector('.btn__text');

  const chip       = document.getElementById('chip');
  const resultCard = document.getElementById('resultCard');
  const finalVerdict = document.getElementById('finalVerdict');
  const verdictIcon  = document.getElementById('verdictIcon');

  const modelCell  = document.getElementById('modelCell');
  const gsbCell    = document.getElementById('gsbCell');
  const vtCell     = document.getElementById('vtCell');

  const rawJson    = document.getElementById('rawJson');

  // --- helpers ---
  function setChip(state){
    chip.classList.remove('chip--ok','chip--bad','chip--warn','chip--idle');
    if(state==='Legitimate'){ chip.classList.add('chip--ok'); chip.textContent='Legitimate'; }
    else if(state==='Phishing'){ chip.classList.add('chip--bad'); chip.textContent='Phishing'; }
    else if(state==='Suspicious'){ chip.classList.add('chip--warn'); chip.textContent='Suspicious'; }
    else { chip.classList.add('chip--idle'); chip.textContent='Idle'; }
  }

  function pill(state){
    const cls = state==='Legitimate' ? 'pill--green' :
                state==='Phishing'   ? 'pill--red'   :
                state==='Suspicious' ? 'pill--yellow' : 'pill--muted';
    return `<span class="pill ${cls}">${state || 'Unknown'}</span>`;
  }

  function iconFor(v){
    if(v==='Legitimate') return `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#15803d" d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z"/></svg>`;
    if(v==='Phishing')   return `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#b91c1c" d="M1 21h22L12 2 1 21zm12-3h-2v2h2v-2zm0-8h-2v6h2V10z"/></svg>`;
    return `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#b45309" d="M12 22a10 10 0 1 1 0-20 10 10 0 0 1 0 20zm-1-7h2v2h-2v-2zm0-9h2v7h-2V6z"/></svg>`;
  }

  function showSpinner(on){
    spinner.hidden = !on;
    analyzeBtn.disabled = on;
    btnText.textContent = on ? 'Analyzing…' : 'Analyze';
  }

  function normalizeDetails(details){
    // Accept both your new and old response shapes
    if(!details || typeof details!=='object') return { model:'Unknown', gsb:'Unknown', vt:'Unknown' };
    const model = details['Phisher Model'] ?? details.model_prediction ?? details.model ?? 'Unknown';
    const gsb   = details['Google Safe Browsing'] ?? details.google_safe_browsing ?? 'Unknown';
    const vt    = details['VirusTotal'] ?? details.virustotal ?? 'Unknown';
    return { model, gsb, vt };
  }

  function renderResult(data){
    const verdict = data.final_verdict || data.verdict || data.status || 'Suspicious';
    const {model, gsb, vt} = normalizeDetails(data.details);

    finalVerdict.textContent = verdict;
    verdictIcon.innerHTML = iconFor(verdict);
    setChip(verdict);

    modelCell.innerHTML = pill(model);
    gsbCell.innerHTML   = pill(gsb);
    vtCell.innerHTML    = pill(vt);

    rawJson.textContent = JSON.stringify(data, null, 2);
    resultCard.hidden = false;
  }

  function showError(msg){
    finalVerdict.textContent = 'Error';
    verdictIcon.innerHTML = iconFor('Suspicious');
    setChip('Suspicious');
    modelCell.innerHTML = `<span class="pill pill--muted">${msg}</span>`;
    gsbCell.innerHTML   = `<span class="pill pill--muted">—</span>`;
    vtCell.innerHTML    = `<span class="pill pill--muted">—</span>`;
    resultCard.hidden = false;
  }

  // --- events ---
  currentBtn.addEventListener('click', async () => {
    try{
      const [tab] = await chrome.tabs.query({active:true, currentWindow:true});
      if(tab && tab.url) urlInput.value = tab.url;
    }catch{}
  });

  analyzeBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if(!url){
      setChip('Suspicious');
      urlInput.focus();
      return;
    }
    showSpinner(true);
    resultCard.hidden = true;

    try{
      const res = await fetch('http://127.0.0.1:5000/analyze', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ url })
      });
      if(!res.ok) throw new Error(`Server ${res.status}`);
      const data = await res.json();
      renderResult(data);
    }catch(e){
      console.error(e);
      showError('Could not reach the local API. Is it running?');
    }finally{
      showSpinner(false);
    }
  });

  // Prefill with current tab on open
  (async () => {
    try{
      const [tab] = await chrome.tabs.query({active:true, currentWindow:true});
      if(tab && tab.url) urlInput.value = tab.url;
    }catch{}
  })();
});
