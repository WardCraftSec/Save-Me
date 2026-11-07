const isIP=s=>/^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const W='https://save-me-proxy.silmarillimum.workers.dev/';

// XSS escape
function esc(s){
  const d=document.createElement('div');
  d.textContent=s;
  return d.innerHTML;
}

// Dark mode
function toggleDarkMode(){
  document.body.classList.toggle('dark');
  const isDark=document.body.classList.contains('dark');
  document.getElementById('darkLabel').textContent=isDark?'☀️ Light mode':'🌙 Dark mode';
  try{localStorage.setItem('sm_dark',isDark?'1':'0')}catch(e){}
}
(function(){
  try{
    if(localStorage.getItem('sm_dark')==='1'){
      document.body.classList.add('dark');
      document.getElementById('darkLabel').textContent='☀️ Light mode';
    }
  }catch(e){}
})();

// Menu
function toggleMenu(){
  document.getElementById('menuDropdown').classList.toggle('visible');
}
document.addEventListener('click',function(){
  document.getElementById('menuDropdown').classList.remove('visible');
});

function showTab(n){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',i===n));
  document.querySelectorAll('.tab-content').forEach((c,i)=>c.classList.toggle('visible',i===n));
  window.scrollTo({top:0,behavior:'smooth'});
  savePosition(n, null);
}

function go(tab,step){
  const prefix='t'+tab;
  document.querySelectorAll('#tab'+tab+' .step').forEach(s=>s.classList.remove('visible'));
  document.querySelectorAll('#bubbles'+tab+' .bubble').forEach((b,i)=>{
    b.classList.remove('active','done');
    if(typeof step==='number'&&i+1<step)b.classList.add('done');
  });
  if(typeof step==='number'){
    const el=document.getElementById(prefix+'s'+step);
    if(el)el.classList.add('visible');
    const bub=document.querySelectorAll('#bubbles'+tab+' .bubble')[step-1];
    if(bub)bub.classList.add('active');
  }else{
    const el=document.getElementById(prefix+'done');
    if(el)el.classList.add('visible');
    document.querySelectorAll('#bubbles'+tab+' .bubble').forEach(b=>b.classList.add('done'));
  }
  const bub=document.getElementById('bubbles'+tab);
  if(bub)bub.scrollIntoView({behavior:'smooth'});
  savePosition(tab, step);
}

function savePosition(tab, step){
  try{
    localStorage.setItem('sm_position', JSON.stringify({tab:tab, step:step||1}));
  }catch(e){}
}

function restorePosition(){
  try{
    const raw=localStorage.getItem('sm_position');
    if(!raw)return;
    const p=JSON.parse(raw);
    if(p&&typeof p.tab==='number'&&p.tab>=0&&p.tab<=4){
      showTab(p.tab);
      if(typeof p.step==='number'&&p.step>1){
        go(p.tab, p.step);
      }
    }
  }catch(e){}
}

function toggleTrouble(stepId){
  const el=document.getElementById('trouble-'+stepId);
  if(el)el.classList.toggle('visible');
}

async function runCheck(){
  const val=document.getElementById('checkInput').value.trim();
  if(!val)return;

  const btn=document.querySelector('.checker form .btn[type="submit"]');
  if(btn){btn.disabled=true;btn.textContent='Checking…'}

  const res=document.getElementById('results');
  res.innerHTML='<p style="text-align:center;color:#64748b">Checking…</p>';
  let target=val,resolvedIP=null,geo=null,org=null,asn=null,usageType=null,abuseScore=null;
  let vtFlagged=0,vtMal=0,vtSusp=0,vtClean=0,vtBreakdown='',vtTopCat='';

  if(!isIP(val)){
    try{
      const r=await fetch(W+'?target='+encodeURIComponent(val)+'&type=resolve');
      const d=await r.json();
      if(d.Answer&&d.Answer.length>0){
        resolvedIP=d.Answer.find(a=>a.type===1)?.data;
        if(resolvedIP)target=resolvedIP;
      }
    }catch(e){}
  }

  try{
    const r=await fetch(W+'?target='+encodeURIComponent(target)+'&type=abuseipdb');
    const d=await r.json();
    if(d.data){abuseScore=d.data.abuseConfidenceScore;usageType=d.data.usageType||'unknown'}
  }catch(e){}

  try{
    const kind=isIP(target)?'ip_addresses':'domains';
    const r=await fetch(W+'?target='+encodeURIComponent(target)+'&type=vt&kind='+kind);
    const d=await r.json();
    if(d.data&&d.data.last_analysis_stats){
      const s=d.data.last_analysis_stats;
      vtMal=s.malicious;vtSusp=s.suspicious;vtClean=s.harmless;vtFlagged=vtMal+vtSusp;
      if(d.data.last_analysis_results){
        const cats={};
        for(const k in d.data.last_analysis_results){
          const r2=d.data.last_analysis_results[k].result;
          if(r2&&r2!=='clean'&&r2!=='unrated')cats[r2]=(cats[r2]||0)+1;
        }
        if(Object.keys(cats).length){
          vtBreakdown='<ul class="breakdown">';
          let topCount=0;
          for(const c in cats){
            vtBreakdown+='<li>'+esc(c)+' — '+cats[c]+' engine'+(cats[c]>1?'s':'')+'</li>';
            if(cats[c]>topCount){topCount=cats[c];vtTopCat=c}
          }
          vtBreakdown+='</ul>';
        }
      }
    }
  }catch(e){}

  try{
    const r=await fetch(W+'?target='+encodeURIComponent(target)+'&type=ipinfo');
    const d=await r.json();
    if(d.city||d.country){geo=(d.city?d.city+', ':'')+d.country;org=d.org||'unknown';asn=d.asn||'unknown'}
  }catch(e){}

  let html='';
  if(resolvedIP)html+='<div class="result-card"><h3>Resolved</h3><p class="detail">'+esc(val)+' → <strong>'+esc(resolvedIP)+'</strong></p></div>';

  let sum='';
  if(geo)sum+=esc(geo)+'.';
  if(org)sum+=' Run by '+esc(org)+'.';
  if(usageType)sum+=' This is a '+(usageType.toLowerCase().includes('residential')?'residential (home)':'datacenter (server)')+' IP.';
  if(vtFlagged>0)sum+=vtFlagged+' security tools flagged it'+(vtTopCat?', mostly for '+esc(vtTopCat):'')+'.';
  else if(vtFlagged===0&&vtClean>0)sum+=' No security tools have flagged it.';
  if(abuseScore!==null&&abuseScore>=50)sum+=' '+abuseScore+'% of recent reports say it is abusive.';
  if(sum)html+='<div class="summary">'+sum+'</div>';

  if(abuseScore!==null){
    const cls=abuseScore>=50?'high':abuseScore>=20?'mid':'low';
    html+='<div class="result-card"><h3>Abuse Reports (AbuseIPDB)</h3><p class="score '+cls+'">'+abuseScore+'%</p><p class="detail">How often other people have reported this as abusive (last 90 days).</p><p class="detail">Type: '+esc(usageType||'unknown')+'</p></div>';
  }

  if(vtFlagged>0||vtClean>0){
    const cls=vtFlagged>=10?'high':vtFlagged>=3?'mid':'low';
    html+='<div class="result-card"><h3>Threat Detection (VirusTotal)</h3><p class="score '+cls+'">'+vtFlagged+' / 92 flagged</p><p class="detail">'+vtMal+' malicious, '+vtSusp+' suspicious, '+vtClean+' clean</p>'+vtBreakdown+
    '<p class="meaning-toggle" onclick="document.getElementById(\'mb\').classList.toggle(\'visible\')">What do these mean? ▼</p>'+
    '<div class="meaning-box" id="mb"><p><strong>Phishing</strong> — tries to trick you into giving up passwords or personal info.<br><strong>Malware</strong> — tries to install harmful software on your device.<br><strong>Suspicious</strong> — unusual activity detected, not confirmed harmful.<br><strong>C2 (Command &amp; Control)</strong> — communication channel for an already-infected device.</p></div></div>';
  }

  if(geo){
    html+='<div class="result-card"><h3>Location &amp; Network (ipinfo)</h3><p class="detail">'+esc(geo)+'<br>Network: '+esc(org)+'<br>ASN: '+esc(asn)+'</p></div>';
  }

  res.innerHTML=html||'<p style="color:#64748b">No results. Try a different input.</p>';
  saveHistory(val);

  if(btn){btn.disabled=false;btn.textContent='Check'}
}

function saveHistory(t){
  let h=[];
  try{h=JSON.parse(localStorage.getItem('sm_history')||'[]')}catch(e){}
  h.unshift({t:t,d:new Date().toLocaleString()});
  if(h.length>20)h=h.slice(0,20);
  localStorage.setItem('sm_history',JSON.stringify(h));
  renderHistory();
}

function renderHistory(){
  let h=[];
  try{h=JSON.parse(localStorage.getItem('sm_history')||'[]')}catch(e){}
  if(!h.length)return;
  let items=h.slice(0,10).map(x=>'<div class="history-item"><strong>'+esc(x.t)+'</strong><br><span class="ts">'+esc(x.d)+'</span></div>').join('');
  document.getElementById('history').innerHTML='<h3>Recent checks</h3>'+items;
}

renderHistory();
restorePosition();   
