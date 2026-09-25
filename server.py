#!/usr/bin/env python3
import base64, json, os, re, secrets, sqlite3, subprocess, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlparse, parse_qs

DB_FILE = os.environ.get("DB_FILE", "/tmp/trojan_users.db")
USERS_FILE = os.environ.get("USERS_FILE", "/tmp/ghanizada-users.json")
XRAY_CONFIG = os.environ.get("XRAY_CONFIG", "/tmp/xray-managed.json")
ACCESS_LOG = "/tmp/xray-access.log"
SNI = os.environ.get("SNI", "firebase-settings.crashlytics.com")
OWNER_KEY = os.environ.get("OWNER_KEY", "Ghanizada")
PORT = int(os.environ.get("DASHBOARD_PORT", "8081"))
START_TIME = time.time()
PROTOCOLS = {
    "trojan": {"name": "Trojan", "path": "/ws/Ghanizada"},
    "vless": {"name": "VLESS", "path": "/ws/VLESS-Ghanizada"},
    "vmess": {"name": "VMess", "path": "/ws/VMess-Ghanizada"},
}


def ensure_files():
    os.makedirs(os.path.dirname(USERS_FILE) or "/tmp", exist_ok=True)
    if not os.path.exists(USERS_FILE):
        save_users([])


def load_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_users(users):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, USERS_FILE)


def public_user(u, host):
    cfg = make_uri(u, host)
    return {
        "id": u["id"], "username": u["username"], "protocol": u["protocol"],
        "credential": u["credential"], "created_at": u["created_at"],
        "online": u["username"] in online_names(), "uri": cfg
    }


def make_uri(u, host):
    p = PROTOCOLS[u["protocol"]]
    path = quote(p["path"], safe="")
    h = quote(host, safe="")
    if u["protocol"] == "trojan":
        return f"trojan://{quote(u['credential'], safe='')}@{host}:443?security=tls&type=ws&path={path}&host={h}&sni={quote(SNI, safe='')}#{quote(u['username'], safe='')}"
    if u["protocol"] == "vless":
        return f"vless://{u['credential']}@{host}:443?encryption=none&security=tls&type=ws&path={path}&host={h}&sni={quote(SNI, safe='')}#{quote(u['username'], safe='')}"
    obj = {"v":"2","ps":u["username"],"add":host,"port":"443","id":u["credential"],"aid":"0","scy":"auto","net":"ws","type":"none","host":host,"path":p["path"],"tls":"tls","sni":SNI}
    return "vmess://" + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def write_xray_config(users):
    clients = {"trojan": [], "vless": [], "vmess": []}
    for u in users:
        if u["protocol"] == "trojan":
            clients["trojan"].append({"password": u["credential"], "email": u["username"]})
        elif u["protocol"] == "vless":
            clients["vless"].append({"id": u["credential"], "email": u["username"], "level": 0})
        else:
            clients["vmess"].append({"id": u["credential"], "email": u["username"], "alterId": 0})
    cfg = {
      "log": {"loglevel":"warning","access":ACCESS_LOG,"error":"/tmp/xray-error.log"},
      "inbounds": [
        {"tag":"trojan-ws","listen":"127.0.0.1","port":10000,"protocol":"trojan","settings":{"clients":clients["trojan"]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":PROTOCOLS["trojan"]["path"]}},"sniffing":{"enabled":True,"destOverride":["http","tls"]}},
        {"tag":"vless-ws","listen":"127.0.0.1","port":10001,"protocol":"vless","settings":{"clients":clients["vless"],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":PROTOCOLS["vless"]["path"]}},"sniffing":{"enabled":True,"destOverride":["http","tls"]}},
        {"tag":"vmess-ws","listen":"127.0.0.1","port":10002,"protocol":"vmess","settings":{"clients":clients["vmess"]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":PROTOCOLS["vmess"]["path"]}},"sniffing":{"enabled":True,"destOverride":["http","tls"]}}
      ],
      "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]
    }
    tmp = XRAY_CONFIG + ".tmp"
    with open(tmp,"w",encoding="utf-8") as f: json.dump(cfg,f,indent=2)
    os.replace(tmp, XRAY_CONFIG)
    open("/tmp/xray-reload","w").close()


def online_names():
    now = time.time(); result = set()
    try:
        with open(ACCESS_LOG,"r",encoding="utf-8",errors="ignore") as f:
            lines = f.readlines()[-1000:]
        for line in lines:
            m = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
            if not m: continue
            try: ts=time.mktime(time.strptime(m.group(1), "%Y/%m/%d %H:%M:%S"))
            except Exception: continue
            if now-ts > 90: continue
            for u in load_users():
                if re.search(rf"(?:email=|\b){re.escape(u['username'])}(?:\b|\s|\")", line):
                    result.add(u["username"])
    except Exception: pass
    return result


def db_init():
    c=sqlite3.connect(DB_FILE); c.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, username TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"); c.commit(); c.close()


def audit(action, username):
    try:
        c=sqlite3.connect(DB_FILE); c.execute("INSERT INTO audit(action,username) VALUES (?,?)",(action,username)); c.commit(); c.close()
    except Exception: pass


def auth(h):
    return h.headers.get("X-Admin-Key", "") == OWNER_KEY


class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, body, content_type, code=200):
        self.send_response(code); self.send_header("Content-Type",content_type); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def json(self,data,code=200): self.send_bytes(json.dumps(data).encode(),"application/json; charset=utf-8",code)
    def read_json(self):
        n=int(self.headers.get("Content-Length","0")); return json.loads(self.rfile.read(n) or b"{}")
    def host(self): return self.headers.get("Host","localhost").split(":")[0]
    def do_GET(self):
        p=urlparse(self.path)
        if p.path=="/": return self.page()
        if p.path=="/healthz": return self.json({"ok":True})
        if p.path=="/api/config": return self.json({"host":self.host(),"protocols":PROTOCOLS,"user_count":len(load_users()),"online_count":len(online_names())}) if auth(self) else self.json({"error":"Unauthorized"},401)
        if p.path=="/api/users":
            if not auth(self): return self.json({"error":"Unauthorized"},401)
            return self.json([public_user(u,self.host()) for u in load_users()])
        if p.path=="/api/stats": return self.json({"active_count":len(online_names()),"total_users":len(load_users()),"ping_ms":round(12+(time.time()*1000%18),1),"uptime":uptime()})
        if p.path=="/api/qr":
            if not auth(self): return self.json({"error":"Unauthorized"},401)
            uid=parse_qs(p.query).get("id",[""])[0]; u=next((x for x in load_users() if x["id"]==uid),None)
            if not u: return self.json({"error":"User not found"},404)
            return self.qr(make_uri(u,self.host()))
        self.send_error(404)
    def do_POST(self):
        if urlparse(self.path).path!="/api/users" or not auth(self): return self.json({"error":"Unauthorized"},401)
        d=self.read_json(); protocol=d.get("protocol"); username=(d.get("username") or "").strip(); credential=(d.get("credential") or "").strip()
        if protocol not in PROTOCOLS or not username: return self.json({"error":"protocol and username are required"},400)
        users=load_users()
        if any(x["username"].lower()==username.lower() for x in users): return self.json({"error":"Username already exists"},409)
        if not credential: credential=str(uuid.uuid4()) if protocol!="trojan" else secrets.token_urlsafe(16)
        if any(x["credential"]==credential for x in users): return self.json({"error":"Credential already exists"},409)
        u={"id":secrets.token_hex(8),"username":username,"protocol":protocol,"credential":credential,"created_at":time.strftime("%Y-%m-%d %H:%M:%S")}
        users.append(u); save_users(users); write_xray_config(users); audit("create",username)
        return self.json(public_user(u,self.host()),201)
    def do_PUT(self):
        parts=urlparse(self.path).path.split("/")
        if len(parts)!=4 or parts[2]!="users" or not auth(self): return self.json({"error":"Unauthorized"},401)
        uid=parts[3]; d=self.read_json(); users=load_users(); u=next((x for x in users if x["id"]==uid),None)
        if not u:return self.json({"error":"User not found"},404)
        newname=(d.get("username") or u["username"]).strip(); cred=(d.get("credential") or u["credential"]).strip()
        if not newname or any(x["id"]!=uid and x["username"].lower()==newname.lower() for x in users): return self.json({"error":"Invalid or duplicate username"},400)
        if any(x["id"]!=uid and x["credential"]==cred for x in users): return self.json({"error":"Credential already exists"},409)
        old=u["username"]; u["username"]=newname; u["credential"]=cred; save_users(users); write_xray_config(users); audit("edit",newname)
        return self.json(public_user(u,self.host()))
    def do_DELETE(self):
        parts=urlparse(self.path).path.split("/")
        if len(parts)!=4 or parts[2]!="users" or not auth(self): return self.json({"error":"Unauthorized"},401)
        uid=parts[3]; users=load_users(); u=next((x for x in users if x["id"]==uid),None)
        if not u:return self.json({"error":"User not found"},404)
        users=[x for x in users if x["id"]!=uid]; save_users(users); write_xray_config(users); audit("delete",u["username"])
        return self.json({"ok":True})
    def qr(self,uri):
        try:
            proc=subprocess.run(["qrencode","-t","SVG","-m","2","-s","6","--inline",uri],capture_output=True,timeout=3,check=True)
            return self.send_bytes(proc.stdout,"image/svg+xml; charset=utf-8")
        except Exception as e:return self.json({"error":"QR generator unavailable","detail":str(e)},503)
    def page(self):
        doc=HTML
        self.send_bytes(doc.encode(),"text/html; charset=utf-8")
    def log_message(self,fmt,*args): pass


def uptime():
    s=int(time.time()-START_TIME); h,r=divmod(s,3600); m,s=divmod(r,60); return f"{h:02d}:{m:02d}:{s:02d}"

HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ghanizada User Manager</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;font-family:system-ui,Arial;background:#06080d;color:#f5f7fb}.wrap{max-width:1100px;margin:auto;padding:18px}.hero,.panel{background:#0d1422;border:1px solid #26324a;border-radius:18px;padding:18px;margin-bottom:14px}.brand{color:#6ea8ff;letter-spacing:3px;font-weight:900;font-size:12px}.title{font-size:27px;font-weight:900;margin:7px 0}.muted{color:#94a3b8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.stat{background:#09101b;border:1px solid #202c42;border-radius:12px;padding:12px}.stat b{display:block;font-size:19px;margin-top:4px}.row{display:flex;gap:8px;flex-wrap:wrap}.input,select{background:#080d15;color:#fff;border:1px solid #334155;border-radius:9px;padding:11px;min-width:0}.input{flex:1}.btn{border:0;border-radius:9px;padding:10px 13px;background:#2563eb;color:#fff;font-weight:800;cursor:pointer}.btn.red{background:#b42318}.btn.gray{background:#1e293b}.table{width:100%;border-collapse:collapse;margin-top:12px}.table th,.table td{padding:10px 7px;border-bottom:1px solid #1e293b;text-align:left;font-size:13px;vertical-align:top}.online{color:#35e39a;font-weight:900}.offline{color:#64748b}.uri{width:100%;min-height:72px;background:#050911;color:#dce7ff;border:1px solid #29364e;border-radius:9px;padding:8px}.qr{background:#fff;border-radius:10px;padding:5px;width:170px;height:170px;display:flex;align-items:center;justify-content:center}.qr svg{width:160px;height:160px}.modal{position:fixed;inset:0;background:#000a;display:none;align-items:center;justify-content:center;padding:18px}.modalbox{background:#0d1422;border:1px solid #334155;border-radius:16px;padding:18px;max-width:520px;width:100%}.small{font-size:12px;color:#94a3b8}@media(max-width:650px){.table th:nth-child(3),.table td:nth-child(3){display:none}}</style></head><body><main class="wrap"><section class="hero"><div class="brand">GHANIZADA • CLOUD RUN</div><div class="title">User Manager</div><div class="muted">Create users after installation. No Trojan, VLESS or VMess users are pre-configured.</div><div class="grid" style="margin-top:13px"><div class="stat">TOTAL USERS<b id="total">0</b></div><div class="stat">ONLINE NOW<b id="online">0</b></div><div class="stat">SERVER<b class="online">● ONLINE</b></div><div class="stat">UPTIME<b id="uptime">—</b></div></div></section><section class="panel" id="login"><h3>Admin Access</h3><div class="row"><input class="input" id="key" type="password" placeholder="Enter admin key"><button class="btn" onclick="login()">LOGIN</button></div><div class="small" style="margin-top:8px">Use the OWNER_KEY printed/configured during deployment.</div></section><section class="panel" id="manager" style="display:none"><h3>Create User</h3><div class="row"><select id="protocol"><option value="trojan">Trojan</option><option value="vless">VLESS</option><option value="vmess">VMess</option></select><input class="input" id="username" placeholder="Username"><input class="input" id="credential" placeholder="Password / UUID (blank = auto)"><button class="btn" onclick="createUser()">CREATE</button></div><div class="small" style="margin-top:8px">Trojan uses a password. VLESS/VMess use UUIDs. Changes restart Xray automatically.</div><div style="overflow:auto"><table class="table"><thead><tr><th>User</th><th>Protocol</th><th>Credential</th><th>Status</th><th>Actions</th></tr></thead><tbody id="users"></tbody></table></div></section><div class="modal" id="modal"><div class="modalbox"><h3 id="mtitle">User</h3><div class="small">Connection URI</div><textarea id="muri" class="uri" readonly></textarea><div class="row" style="margin-top:9px"><button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('muri').value)">COPY URI</button><button class="btn gray" onclick="closeModal()">CLOSE</button></div><div id="mqr" class="qr" style="margin-top:12px"></div></div></div></main><script>let KEY=localStorage.getItem('ghanizada_admin')||'';function H(){return {'X-Admin-Key':KEY,'Content-Type':'application/json'}}function login(){KEY=document.getElementById('key').value.trim();localStorage.setItem('ghanizada_admin',KEY);loadUsers().catch(()=>{alert('Invalid admin key');localStorage.removeItem('ghanizada_admin');KEY=''})}async function api(url,opt={}){let r=await fetch(url,{...opt,headers:{...H(),...(opt.headers||{})}});let d=await r.json();if(!r.ok)throw new Error(d.error||'Request failed');return d}async function loadUsers(){if(!KEY)throw Error('login');let u=await api('/api/users');document.getElementById('login').style.display='none';document.getElementById('manager').style.display='block';document.getElementById('total').textContent=u.length;document.getElementById('online').textContent=u.filter(x=>x.online).length;document.getElementById('users').innerHTML=u.map(x=>`<tr><td><b>${esc(x.username)}</b></td><td>${esc(x.protocol)}</td><td style="max-width:230px;word-break:break-all">${esc(x.credential)}</td><td class="${x.online?'online':'offline'}">${x.online?'● ONLINE':'● OFFLINE'}</td><td><button class="btn gray" onclick='showUser(${JSON.stringify(x)})'>URI/QR</button> <button class="btn gray" onclick='editUser(${JSON.stringify(x)})'>EDIT</button> <button class="btn red" onclick='deleteUser("${x.id}")'>DELETE</button></td></tr>`).join('')}function esc(s){return String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}async function createUser(){try{await api('/api/users',{method:'POST',body:JSON.stringify({protocol:document.getElementById('protocol').value,username:document.getElementById('username').value,credential:document.getElementById('credential').value})});document.getElementById('username').value='';document.getElementById('credential').value='';await loadUsers();alert('User created')}catch(e){alert(e.message)}}async function editUser(u){let n=prompt('Username:',u.username);if(n===null)return;let c=prompt('Password / UUID:',u.credential);if(c===null)return;try{await api('/api/users/'+u.id,{method:'PUT',body:JSON.stringify({username:n,credential:c})});await loadUsers();alert('User updated')}catch(e){alert(e.message)}}async function deleteUser(id){if(!confirm('Delete this user?'))return;try{await api('/api/users/'+id,{method:'DELETE'});await loadUsers()}catch(e){alert(e.message)}}async function showUser(u){document.getElementById('mtitle').textContent=u.username+' • '+u.protocol;document.getElementById('muri').value=u.uri;document.getElementById('mqr').innerHTML='Loading…';document.getElementById('modal').style.display='flex';try{let r=await fetch('/api/qr?id='+encodeURIComponent(u.id),{headers:{'X-Admin-Key':KEY}});document.getElementById('mqr').innerHTML=await r.text()}catch(e){document.getElementById('mqr').textContent='QR unavailable'}}function closeModal(){document.getElementById('modal').style.display='none'}async function refresh(){if(!KEY)return;try{await loadUsers();let s=await fetch('/api/stats').then(r=>r.json());document.getElementById('online').textContent=s.active_count;document.getElementById('uptime').textContent=s.uptime}catch(e){}}if(KEY)loadUsers().catch(()=>{});setInterval(refresh,5000);</script></body></html>'''

if __name__ == "__main__":
    ensure_files(); db_init();
    if not os.path.exists(XRAY_CONFIG):
        write_xray_config(load_users())
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
