"""Local web UI (FastAPI).

A single-page control panel served at http://127.0.0.1:8000 by default. It lets
you set the target + identities, pick scanners/integrations, launch a scan, watch
progress stream in real time (Server-Sent Events), and browse findings. It binds
to loopback only.

Run via:  python -m deluluscan.cli --config config.yaml --web
"""
from __future__ import annotations

import json
import queue
import threading
from dataclasses import asdict

from ..config import Config
from ..models import Identity, IdentityRole
from ..orchestrator import Orchestrator

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
    import uvicorn
except ImportError:  # pragma: no cover
    FastAPI = None


_INDEX = """<!doctype html><html><head><meta charset='utf-8'>
<title>deluluscan</title><style>
body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{padding:1rem 1.5rem;background:#161b22;border-bottom:1px solid #30363d}
header h1{margin:0;font-size:1.1rem}
.wrap{display:grid;grid-template-columns:340px 1fr;gap:0;height:calc(100vh - 56px)}
.panel{padding:1.2rem;border-right:1px solid #30363d;overflow:auto}
.feed{padding:1.2rem;overflow:auto}
label{display:block;margin:.6rem 0 .2rem;font-size:.8rem;color:#8b949e}
input,select{width:100%;padding:.4rem;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:.3rem;box-sizing:border-box}
button{margin-top:1rem;padding:.5rem 1rem;background:#238636;color:#fff;border:0;border-radius:.4rem;cursor:pointer}
.f{background:#161b22;border:1px solid #30363d;border-left-width:4px;border-radius:.4rem;padding:.5rem .8rem;margin:.5rem 0}
.f.critical{border-left-color:#b00020}.f.high{border-left-color:#d9480f}
.f.medium{border-left-color:#b8860b}.f.low{border-left-color:#2b6cb0}.f.info{border-left-color:#555}
.badge{font-size:.7rem;padding:.05rem .4rem;border-radius:.3rem;background:#30363d}
.log{font-family:ui-monospace,monospace;font-size:.78rem;color:#8b949e;white-space:pre-wrap}
small{color:#6e7681}
</style></head><body>
<header><h1>deluluscan · the target API security console <small>(authorized testing only)</small></h1></header>
<div class='wrap'>
 <div class='panel'>
  <label>Base URL</label><input id='base' value='http://localhost:8080'>
  <label>Admin user</label><input id='au' placeholder='admin@example.com'>
  <label>Admin password</label><input id='ap' type='password'>
  <label>Back-end user</label><input id='bu' placeholder='editor@example.com'>
  <label>Back-end password</label><input id='bp' type='password'>
  <label>Scanners</label><input id='sc' value='idor,xss,sqli,ssrf,owasp'>
  <label>AI provider</label><select id='ai'><option value='none'>none</option>
   <option value='anthropic'>anthropic</option><option value='ollama'>ollama</option>
   <option value='claude_code'>claude_code (local CLI, no API key)</option></select>
  <label><input type='checkbox' id='state' style='width:auto'> allow state-changing checks (own resources)</label>
  <button onclick='run()'>Start scan</button>
  <p><small>Binds to loopback. Target must be loopback/private unless allow_remote is set in config.</small></p>
 </div>
 <div class='feed'>
  <div id='log' class='log'></div>
  <div id='findings'></div>
 </div>
</div>
<script>
function run(){
 document.getElementById('findings').innerHTML='';
 const log=document.getElementById('log'); log.textContent='';
 const cfg={base_url:base.value,scanners:sc.value,ai:ai.value,
   allow_state_changing:state.checked,
   admin:{username:au.value,password:ap.value},
   backend:{username:bu.value,password:bp.value}};
 fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},
   body:JSON.stringify(cfg)}).then(()=>{
   const es=new EventSource('/api/stream');
   es.onmessage=e=>{const d=JSON.parse(e.data);
     if(d.event==='finding'){addFinding(d.data);}
     else if(d.event==='done'){log.textContent+='\\n[done] '+d.data.duration_s+'s';es.close();}
     else{log.textContent+='\\n'+d.event+': '+JSON.stringify(d.data);}
     log.scrollTop=log.scrollHeight;};
 });
}
function addFinding(f){
 const el=document.createElement('div');el.className='f '+f.severity;
 el.innerHTML='<span class=badge>'+f.severity+'</span> <b>'+f.title+'</b> <small>['+f['class']+']</small>';
 document.getElementById('findings').prepend(el);
}
</script></body></html>"""


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8000) -> None:
    if FastAPI is None:
        raise SystemExit("FastAPI/uvicorn not installed. pip install fastapi uvicorn")

    app = FastAPI(title="deluluscan")
    state = {"q": queue.Queue(), "running": False, "result": None}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _INDEX

    @app.post("/api/scan")
    async def scan(req: Request):
        body = await req.json()
        # Build a fresh config from the panel + base config defaults.
        run_cfg = cfg
        run_cfg.base_url = body.get("base_url", cfg.base_url)
        run_cfg.scan.scanners = [s.strip() for s in body.get("scanners", "idor").split(",")]
        run_cfg.scan.allow_state_changing = bool(body.get("allow_state_changing"))
        run_cfg.ai.provider = body.get("ai", "none")
        admin = body.get("admin", {})
        backend = body.get("backend", {})
        run_cfg.identities[IdentityRole.ADMIN.value] = Identity(
            role=IdentityRole.ADMIN, username=admin.get("username"),
            password=admin.get("password"))
        run_cfg.identities[IdentityRole.BACKEND.value] = Identity(
            role=IdentityRole.BACKEND, username=backend.get("username"),
            password=backend.get("password"))
        run_cfg.identities.setdefault(IdentityRole.ANON.value,
                                      Identity(role=IdentityRole.ANON))

        q = state["q"] = queue.Queue()

        def progress(ev, data):
            q.put({"event": ev, "data": data})

        def worker():
            try:
                state["result"] = Orchestrator(run_cfg, progress=progress).run()
            except SystemExit as exc:
                q.put({"event": "error", "data": {"error": str(exc)}})
            finally:
                q.put(None)  # sentinel

        threading.Thread(target=worker, daemon=True).start()
        return JSONResponse({"started": True})

    @app.get("/api/stream")
    def stream():
        def gen():
            q = state["q"]
            while True:
                item = q.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item)}\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/api/result")
    def result():
        return JSONResponse(state["result"] or {})

    uvicorn.run(app, host=host, port=port, log_level="warning")
