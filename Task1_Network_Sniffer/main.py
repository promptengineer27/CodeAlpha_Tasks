"""
====================================================================================================
NETWORK SNIFFER PRO - COMPLETE UNIFIED VERSION v2.0
====================================================================================================
"""

from flask import Flask, render_template_string, jsonify, request, session, redirect
from datetime import datetime
import json
import os
import sys
import time
import hashlib
import threading
import socket
import subprocess
import platform
import re
import sqlite3
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
DB_FILE = "sniffer.db"
SERVICE_MAP = {80:"HTTP",443:"HTTPS",53:"DNS",22:"SSH",21:"FTP",25:"SMTP",110:"POP3",143:"IMAP",3306:"MySQL",3389:"RDP",8080:"HTTP-ALT"}
DEFAULT_ANSWER = "codealpha"

# ==================== DATABASE ====================
class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()
    
    def _init(self):
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password_hash TEXT,salt TEXT,role TEXT DEFAULT 'user',email TEXT,security_answer TEXT,attempts INTEGER DEFAULT 0,locked INTEGER DEFAULT 0,usage_count INTEGER DEFAULT 0,last_reset TEXT,created_at TEXT);
            CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,start_time TEXT,end_time TEXT,total_packets INTEGER,total_bytes INTEGER,duration REAL,filter_used TEXT);
            CREATE TABLE IF NOT EXISTS threats(id INTEGER PRIMARY KEY AUTOINCREMENT,session_id INTEGER,type TEXT,severity TEXT,src_ip TEXT,dst_ip TEXT,description TEXT,recommendation TEXT,detected_at TEXT);
            CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,action TEXT,details TEXT,ip TEXT,timestamp TEXT);
        ''')
        self.conn.commit()
        c = self.conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not c:
            s = os.urandom(16).hex()
            h = hashlib.sha256(("Admin@123"+s).encode()).hexdigest()
            self.conn.execute("INSERT INTO users(username,password_hash,salt,role,email,security_answer,created_at) VALUES(?,?,?,?,?,?,?)",
                ("admin",h,s,"admin","admin@sniffer.local","codealpha",datetime.now().isoformat()))
            self.conn.commit()
    
    def log(self, username, action, details="", ip="127.0.0.1"):
        self.conn.execute("INSERT INTO logs(username,action,details,ip,timestamp) VALUES(?,?,?,?,?)",
            (username,action,details,ip,datetime.now().isoformat()))
        self.conn.commit()

db = Database()

# ==================== HELPERS ====================
def is_strong(pw):
    if len(pw)<8: return False,"8+ characters required"
    if not re.search(r'[A-Z]',pw): return False,"UPPERCASE letter required"
    if not re.search(r'[a-z]',pw): return False,"lowercase letter required"
    if not re.search(r'\d',pw): return False,"NUMBER required"
    if not re.search(r'[!@#$%^&*()_+\-=]',pw): return False,"SPECIAL character required"
    return True,"Strong"

# ==================== AUTH ====================
class Auth:
    def _hash(self,pw,s=None):
        if s is None: s=os.urandom(16).hex()
        return hashlib.sha256((pw+s).encode()).hexdigest(),s
    
    def add(self,u,p,r="user",e="",sa=DEFAULT_ANSWER):
        if db.conn.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone():
            return False,"Username exists"
        ok,msg=is_strong(p)
        if not ok: return False,msg
        h,s=self._hash(p)
        db.conn.execute("INSERT INTO users(username,password_hash,salt,role,email,security_answer,created_at) VALUES(?,?,?,?,?,?,?)",
            (u,h,s,r,e,sa.lower(),datetime.now().isoformat()))
        db.conn.commit()
        return True,"Created"
    
    def check(self,u,p):
        row=db.conn.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
        if not row: return False,"User not found",None
        if row['locked']: return False,"Account locked",None
        h,_=self._hash(p,row['salt'])
        if h==row['password_hash']:
            db.conn.execute("UPDATE users SET attempts=0 WHERE username=?",(u,))
            db.conn.commit()
            return True,"OK",row['role']
        att=row['attempts']+1
        db.conn.execute("UPDATE users SET attempts=? WHERE username=?",(att,u))
        if att>=5: db.conn.execute("UPDATE users SET locked=1 WHERE username=?",(u,))
        db.conn.commit()
        return False,f"Wrong ({5-att} left)",None
    
    def change_pw(self,u,old,new):
        ok,msg,_=self.check(u,old)
        if not ok: return False,msg
        ok,msg=is_strong(new)
        if not ok: return False,msg
        h,s=self._hash(new)
        db.conn.execute("UPDATE users SET password_hash=?,salt=?,attempts=0,locked=0 WHERE username=?",(h,s,u))
        db.conn.commit()
        return True,"Changed"
    
    def reset_pw(self,u,sa,new):
        row=db.conn.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
        if not row: return False,"Not found"
        if sa.lower()!=row['security_answer']: return False,"Wrong answer"
        ok,msg=is_strong(new)
        if not ok: return False,msg
        h,s=self._hash(new)
        db.conn.execute("UPDATE users SET password_hash=?,salt=?,attempts=0,locked=0 WHERE username=?",(h,s,u))
        db.conn.commit()
        return True,"Reset OK"
    
    def delete_user(self,admin,target):
        if target=='admin': return False,"Protected"
        if db.conn.execute("SELECT role FROM users WHERE username=?",(admin,)).fetchone()['role']!='admin':
            return False,"Admin only"
        db.conn.execute("DELETE FROM users WHERE username=?",(target,))
        db.conn.commit()
        return True,"Deleted"
    
    def all_users(self):
        return [dict(r) for r in db.conn.execute("SELECT username,role,email,created_at,locked FROM users").fetchall()]

auth=Auth()

# ==================== THREAT DETECTOR ====================
class ThreatDetector:
    def __init__(self):
        self.bad_ports={23:"Telnet",445:"SMB",1433:"MSSQL",3306:"MySQL",3389:"RDP",4444:"Metasploit",1337:"Backdoor",31337:"Malware",6667:"Botnet"}
        self.attempts=defaultdict(list)
    
    def analyze(self,p):
        threats=[]
        dp=p.get('dst_port',0);sp=p.get('src_ip','').split(':')[0];dip=p.get('dst_ip','').split(':')[0];sz=p.get('size',0)
        if dp in self.bad_ports:
            threats.append({"type":"suspicious_port","severity":"MEDIUM","description":f"Suspicious port {dp} ({self.bad_ports[dp]})","src_ip":sp,"dst_ip":dip,"recommendation":"Verify if legitimate"})
        if p.get('protocol')=='TCP' and 'S' in p.get('flags',''):
            k=sp;self.attempts[k].append({'t':datetime.now(),'p':dp})
            self.attempts[k]=[a for a in self.attempts[k] if (datetime.now()-a['t']).seconds<60]
            if len(set(a['p'] for a in self.attempts[k]))>10:
                threats.append({"type":"port_scan","severity":"HIGH","description":f"Port scan from {sp}","src_ip":sp,"dst_ip":dip,"recommendation":"Block IP"})
        if sz>10000:
            threats.append({"type":"large_transfer","severity":"MEDIUM","description":f"Large transfer {sz}B","src_ip":sp,"dst_ip":dip,"recommendation":"Monitor"})
        if dp in [21,23,80,110,143]:
            threats.append({"type":"clear_text","severity":"LOW","description":f"Unencrypted {SERVICE_MAP.get(dp,'')}","src_ip":sp,"dst_ip":dip,"recommendation":"Use encrypted alternative"})
        return threats
    
    def summary(self,threats):
        if not threats: return {"total":0,"risk":"LOW","summary":"No threats detected","recs":["Normal monitoring"]}
        sc=defaultdict(int)
        for t in threats: sc[t['severity']]+=1
        risk="LOW"
        if sc.get('CRITICAL',0): risk="CRITICAL"
        elif sc.get('HIGH',0): risk="HIGH"
        elif sc.get('MEDIUM',0)>2: risk="MEDIUM"
        return {"total":len(threats),"risk":risk,"by_severity":dict(sc),"recs":list(set(t['recommendation'] for t in threats))[:5]}

# ==================== CAPTURE ENGINE ====================
class CaptureEngine:
    def __init__(self):
        self.detector = ThreatDetector()
        self.reset()
    
    def reset(self):
        self.pkts=[];self.cnt=0;self.bytes=0;self.proto=defaultdict(int)
        self.svc=defaultdict(int);self.ips=defaultdict(int);self.run=False
        self.st=None;self.alerts=[];self.raw=[];self.all_threats=[]
    
    def handle(self,p):
        if not self.run: return
        self.cnt+=1;self.raw.append(p);ts=datetime.now().strftime("%H:%M:%S")
        if IP in p:
            ip=p[IP];self.bytes+=ip.len;self.ips[ip.src]+=1
            info={"count":self.cnt,"time":ts,"src":ip.src,"dst":ip.dst,"size":ip.len,"protocol":"IP","service":"","flags":"","src_port":0,"dst_port":0}
            if TCP in p:
                t=p[TCP];info["protocol"]="TCP";info["src"]+=f":{t.sport}";info["dst"]+=f":{t.dport}"
                info["flags"]=str(t.flags);info["service"]=SERVICE_MAP.get(t.dport,"")
                info["src_port"]=t.sport;info["dst_port"]=t.dport
                self.proto["TCP"]+=1;self.svc[SERVICE_MAP.get(t.dport,"OTHER")]+=1
            elif UDP in p:
                u=p[UDP];info["protocol"]="UDP";info["src"]+=f":{u.sport}";info["dst"]+=f":{u.dport}"
                info["service"]=SERVICE_MAP.get(u.dport,"");info["src_port"]=u.sport;info["dst_port"]=u.dport
                self.proto["UDP"]+=1;self.svc[SERVICE_MAP.get(u.dport,"OTHER")]+=1
            elif ICMP in p:
                info["protocol"]="ICMP";self.proto["ICMP"]+=1
            
            threats=self.detector.analyze(info)
            self.all_threats.extend(threats)
            for t in threats:
                self.alerts.append(f"[{t['severity']}] {t['description']}")
            
            self.pkts.append(info)
            if len(self.pkts)>200: self.pkts=self.pkts[-200:]
    
    def start(self,c=50,f=""):
        self.reset();self.run=True;self.st=time.time()
        t=threading.Thread(target=lambda:sniff(prn=self.handle,filter=f if f else None,count=c,timeout=120,store=False))
        t.daemon=True;t.start()
    
    def stop(self): self.run=False
    
    def stats(self):
        e=time.time()-self.st if self.st else 0
        return {"total_count":self.cnt,"total_bytes":self.bytes,"duration":round(e,1),"pps":round(self.cnt/e,1) if e>0 else 0,"protocols":dict(self.proto),"services":dict(self.svc),"packets":self.pkts[-50:],"alerts":self.alerts[-10:],"is_running":self.run,"top_ips":sorted(self.ips.items(),key=lambda x:x[1],reverse=True)[:5]}
    
    def export(self):
        if not self.raw: return None
        os.makedirs("captures",exist_ok=True)
        fn=f"captures/cap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(fn,self.raw);return fn
    
    def ai(self):
        if self.cnt==0: return {"error":"No data"}
        t=self.cnt or 1;a={"summary":[],"score":10,"findings":[],"recs":[]}
        tp=(self.proto.get("TCP",0)/t)*100;up=(self.proto.get("UDP",0)/t)*100
        if tp>50: a["summary"].append(f"Web browsing ({tp:.0f}% TCP)")
        if up>20: a["summary"].append(f"Real-time traffic ({up:.0f}% UDP)")
        hc=self.svc.get("HTTPS",0);ic=self.svc.get("HTTP",0);dc=self.svc.get("DNS",0)
        if hc: a["summary"].append(f"{hc} HTTPS (secure)")
        if ic:
            a["summary"].append(f"WARNING: {ic} HTTP (unencrypted)");a["score"]-=2
            a["findings"].append("HTTP traffic visible on network")
        if dc: a["summary"].append(f"{dc} DNS lookups")
        av=self.bytes/t if t>0 else 0
        if av<100: a["summary"].append("Small control packets")
        elif av>500: a["summary"].append(f"Data transfer (avg {av:.0f}B)")
        if ic: a["recs"].append("Use HTTPS websites")
        if dc>20: a["recs"].append("Try faster DNS: 8.8.8.8")
        if not a["findings"]: a["findings"].append("No security issues detected")
        if not a["recs"]: a["recs"].append("Network looks healthy")
        a["score"]=max(1,a["score"]);return a
    
    def threat_report(self):
        return self.detector.summary(self.all_threats)

capture=CaptureEngine()

# ==================== PDF ====================
class PDFGen:
    def generate(self,data,threats,fn=None):
        if not fn: fn=f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        os.makedirs("reports",exist_ok=True)
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor, white
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.enums import TA_CENTER
            doc=SimpleDocTemplate(fn,pagesize=A4);s=getSampleStyleSheet();el=[]
            ts=ParagraphStyle('T',parent=s['Title'],fontSize=20,textColor=HexColor('#0d7377'),alignment=TA_CENTER)
            hs=ParagraphStyle('H',parent=s['Heading2'],fontSize=14,textColor=HexColor('#1a2a3a'))
            ns=ParagraphStyle('N',parent=s['Normal'],fontSize=11)
            el.append(Paragraph("Network Security Report",ts))
            el.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",ns));el.append(Spacer(1,15))
            el.append(Paragraph("Summary",hs))
            sd=[['Metric','Value'],['Packets',str(data.get('total_count',0))],['Data',f"{data.get('total_bytes',0)/1024:.1f} KB"],['Duration',f"{data.get('duration',0)}s"]]
            t=Table(sd,colWidths=[200,200]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),HexColor('#0d7377')),('TEXTCOLOR',(0,0),(-1,0),white),('GRID',(0,0),(-1,-1),1,HexColor('#ccc'))]))
            el.append(t);el.append(Spacer(1,15))
            el.append(Paragraph("Threats",hs))
            if threats.get('total',0)>0:
                el.append(Paragraph(f"Risk: {threats.get('risk','?')}",ns))
                for r in threats.get('recs',[]): el.append(Paragraph(f"- {r}",ns))
            else: el.append(Paragraph("No threats detected",ns))
            el.append(Spacer(1,20));el.append(Paragraph("Generated by Network Sniffer Pro v10.0",s['Italic']))
            doc.build(el);return fn
        except ImportError:
            return None
        except Exception as e:
            print(f"PDF Error: {e}");return None

pdfgen=PDFGen()

# ==================== DIAGNOSTICS ====================
def diagnostics():
    r={"latency":[],"dns":0,"issues":[],"recs":[]}
    try:
        pn="-n" if platform.system().lower()=="windows" else "-c"
        res=subprocess.run(["ping",pn,"4","8.8.8.8"],capture_output=True,text=True,timeout=15)
        for l in res.stdout.split('\n'):
            if "time=" in l or "time<" in l:
                for t in re.findall(r'time[=<](\d+)',l): r["latency"].append(int(t))
    except: r["issues"].append("Ping failed")
    try:
        st=time.time();socket.gethostbyname("google.com")
        r["dns"]=round((time.time()-st)*1000)
        if r["dns"]>200: r["issues"].append(f"Slow DNS ({r['dns']}ms)");r["recs"].append("Use 8.8.8.8 or 1.1.1.1")
    except: r["issues"].append("DNS failed")
    if r["latency"]:
        r["avg"]=round(sum(r["latency"])/len(r["latency"]),1)
        if r["avg"]>150: r["issues"].append(f"High latency ({r['avg']}ms)");r["recs"].append("Check WiFi or switch to wired")
    return r

# ==================== HTML ====================
HTML=r'''
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Network Sniffer Pro v10.0</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0a0e17;color:#c0c0c0}
.navbar{background:#111827;padding:15px 30px;display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #1e3a5f;flex-wrap:wrap}
.navbar h1{color:#00d4ff;font-size:20px}.navbar .user{color:#888;font-size:13px}
.navbar a{color:#f44336;text-decoration:none;margin-left:12px;font-size:13px}.navbar a.al{color:#ff9800}
.container{max-width:1500px;margin:0 auto;padding:20px}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}
.stc{background:#111827;padding:15px;border-radius:8px;border-top:3px solid #00d4ff}
.stc .v{font-size:26px;font-weight:bold;color:#00d4ff}.stc .l{color:#666;font-size:11px;margin-top:4px}
.panel{background:#111827;padding:20px;border-radius:8px;margin-bottom:20px}
.panel h3{color:#00d4ff;margin-bottom:15px;font-size:15px}
.btn{padding:8px 16px;border:none;border-radius:5px;cursor:pointer;font-size:13px;margin:2px;transition:0.3s}
.bs{background:#00c853;color:#000}.bq{background:#f44336;color:#fff}.be{background:#2196f3;color:#fff}
.bd{background:#ff9800;color:#000}.ba{background:#9c27b0;color:#fff}.bt{background:#e91e63;color:#fff}
.bp{background:#4caf50;color:#fff}.btn:disabled{opacity:0.4;cursor:not-allowed}
table{width:100%;border-collapse:collapse;font-size:11px}th{background:#1a2535;padding:8px;text-align:left;color:#00d4ff}
td{padding:6px 8px;border-bottom:1px solid #1a2535}tr:hover{background:#1a2535}
.tcp{color:#4caf50}.udp{color:#ff9800}.icmp{color:#e91e63}
.bw{margin:6px 0}.bl{display:flex;justify-content:space-between;font-size:12px;margin-bottom:2px}
.b{height:16px;background:#1a2535;border-radius:8px;overflow:hidden}
.bf{height:100%;border-radius:8px;transition:width 0.5s}
.alr{padding:6px 10px;margin:3px 0;border-radius:4px;font-size:12px}
.aw{background:#ff980022;border-left:3px solid #ff9800}.ao{background:#4caf5022;border-left:3px solid #4caf50}
.ae{background:#f4433622;border-left:3px solid #f44336}
input,select{background:#1a2535;color:#fff;border:1px solid #2a3a5a;padding:8px;border-radius:4px;font-size:13px;width:100%;margin:5px 0}
input:focus{border-color:#00d4ff;outline:none}
.tab{display:inline-block;padding:8px 16px;cursor:pointer;border-bottom:2px solid transparent;margin-right:3px;font-size:13px}
.tab.active{border-bottom:2px solid #00d4ff;color:#00d4ff}.tc{display:none}.tc.active{display:block}
.ld{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.ln{background:#4caf50;animation:pulse 1s infinite}.lf{background:#f44336}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
.lbox{max-width:420px;margin:50px auto;background:#111827;padding:35px;border-radius:10px}
.lbox h2{color:#00d4ff;margin-bottom:18px;text-align:center}
.lbox .links{text-align:center;margin-top:12px}.lbox .links a{color:#00d4ff;margin:0 8px;font-size:12px;text-decoration:none}
.msg{padding:10px;border-radius:5px;margin:8px 0;text-align:center;font-size:13px}
.mo{background:#4caf5033;color:#4caf50}.me{background:#f4433633;color:#f44336}
.pr{font-size:10px;color:#888;margin:5px 0}.pr span{color:#ff9800}
.ifm{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.ifm input{width:auto}
.g2{display:grid;grid-template-columns:1.5fr 1fr;gap:20px}.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
</style></head><body>
{% if not session.user %}
<div class="lbox"><h2>🔐 Network Sniffer Pro v10.0</h2>
{% if msg %}<div class="msg {{'mo' if mt=='ok' else 'me'}}">{{msg}}</div>{% endif %}
{% if page=='register' %}
<form method="POST" action="/register">
<input type="text" name="username" placeholder="Username" required>
<input type="email" name="email" placeholder="Email (optional)">
<input type="password" name="password" placeholder="Password" required>
<div class="pr">🔒 Password: <span>8+ chars, UPPERCASE, lowercase, number, special char</span></div>
<input type="password" name="confirm" placeholder="Confirm Password" required>
<input type="text" name="sa" placeholder="Security Answer (for recovery)" value="codealpha">
<div class="pr">💡 Remember this answer for password recovery!</div>
<button class="btn bs" type="submit" style="width:100%">Create Account</button></form>
<div class="links"><a href="/login">← Login</a></div>
{% elif page=='forgot' %}
<h3 style="color:#ff9800;text-align:center;">🔑 Reset Password</h3>
<form method="POST" action="/forgot">
<input type="text" name="username" placeholder="Username" required>
<input type="text" name="sa" placeholder="Security Answer" required>
<input type="password" name="new_password" placeholder="New Password" required>
<input type="password" name="confirm" placeholder="Confirm" required>
<button class="btn bd" type="submit" style="width:100%">Reset Password</button></form>
<div class="links"><a href="/login">← Login</a></div>
{% else %}
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button class="btn bs" type="submit" style="width:100%">🔑 Login</button></form>
<div class="links"><a href="/register">Register</a> | <a href="/forgot">Forgot?</a> | <a href="/guest">Guest</a></div>
<p style="text-align:center;color:#555;margin-top:12px;font-size:11px;">Default: admin / Admin@123</p>
{% endif %}</div>
{% else %}
<div class="navbar"><div><h1>🔐 Network Sniffer Pro v10.0</h1></div><div class="user">👤 {{session.user}} ({{session.role}}){% if session.role=='admin' %} <a href="/admin" class="al">⚙ Admin</a>{% endif %} <a href="/logout">Logout</a></div></div>
{% if admin_panel %}
<div class="container"><div class="panel"><h3>⚙ Admin Panel</h3>
{% if am %}<div class="msg {{'mo' if amt=='ok' else 'me'}}">{{am}}</div>{% endif %}
<h4 style="margin:20px 0 10px;color:#00d4ff;">Change Password</h4>
<form method="POST" action="/admin/cpw" class="ifm">
<input type="password" name="old" placeholder="Current" required style="width:160px;">
<input type="password" name="new" placeholder="New" required style="width:160px;">
<input type="password" name="confirm" placeholder="Confirm" required style="width:160px;">
<button class="btn bp" type="submit">Change</button></form>
<h4 style="margin:25px 0 10px;color:#00d4ff;">Users</h4>
<table><thead><tr><th>Username</th><th>Role</th><th>Email</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>
{% for u in ulist %}<tr><td><b>{{u.username}}</b></td><td>{{u.role}}</td><td>{{u.email}}</td><td>{{u.created_at}}</td><td>{{'🔒 Locked' if u.locked else '✅ Active'}}</td>
<td>{% if u.username!='admin' %}<form method="POST" action="/admin/del" style="display:inline" onsubmit="return confirm('Delete {{u.username}}?')"><input type="hidden" name="target" value="{{u.username}}"><button class="btn bq" type="submit" style="padding:4px 10px;font-size:11px;">🗑</button></form>{% else %}<span style="color:#555;">Protected</span>{% endif %}</td></tr>{% endfor %}</tbody></table>
<p style="margin-top:15px;"><a href="/" style="color:#00d4ff;text-decoration:none;">← Dashboard</a></p></div></div>
{% else %}
<div class="container">
<div class="stats">
<div class="stc"><div class="v" id="cnt">0</div><div class="l">Packets</div></div>
<div class="stc"><div class="v" id="byt">0 KB</div><div class="l">Data</div></div>
<div class="stc"><div class="v" id="dur">0s</div><div class="l">Duration</div></div>
<div class="stc"><div class="v" id="pps">0</div><div class="l">Pkts/s</div></div>
<div class="stc"><div class="v" id="scr">-</div><div class="l">Security</div></div>
<div class="stc"><div class="v" id="thr">-</div><div class="l">Threats</div></div>
</div>
<div class="panel"><span class="ld lf" id="dot"></span>
<button class="btn bs" onclick="start()" id="bStart">▶ Start</button>
<button class="btn bq" onclick="stop()" id="bStop" disabled>⏹ Stop</button>
<button class="btn be" onclick="exportPCAP()">💾 PCAP</button>
<button class="btn bd" onclick="runDiag()">🔧 Diag</button>
<button class="btn ba" onclick="showAI()">🤖 AI</button>
<button class="btn bt" onclick="showThreats()">🛡 Threats</button>
<button class="btn bp" onclick="genPDF()">📄 PDF</button>
<span style="margin-left:15px;"><input type="number" id="pktC" value="50" style="width:60px;display:inline;"><input type="text" id="filt" placeholder="Filter" style="width:140px;display:inline;"></span></div>
<div style="margin-bottom:12px;">
<div class="tab active" onclick="st('live')">📦 Live</div>
<div class="tab" onclick="st('stats')">📊 Stats</div>
<div class="tab" onclick="st('ai')">🤖 AI</div>
<div class="tab" onclick="st('threats')">🛡 Threats</div>
<div class="tab" onclick="st('diag')">🔧 Diag</div>
</div>
<div class="tc active" id="t-live"><div class="g2"><div class="panel"><h3>Live Feed</h3><div style="max-height:380px;overflow-y:auto;"><table><thead><tr><th>#</th><th>Time</th><th>Proto</th><th>Source</th><th>Destination</th><th>Size</th><th>Svc</th></tr></thead><tbody id="pBody"><tr><td colspan="7" style="text-align:center;color:#555;">No packets</td></tr></tbody></table></div></div><div><div class="panel"><h3>🚨 Alerts</h3><div id="aBox"><p style="color:#555;">Waiting...</p></div></div><div class="panel"><h3>🔍 Top IPs</h3><div id="tIPs"><p style="color:#555;">No data</p></div></div></div></div></div>
<div class="tc" id="t-stats"><div class="g3"><div class="panel"><h3>Protocols</h3><div id="pBars"></div></div><div class="panel"><h3>Services</h3><div id="tSvc"></div></div><div class="panel"><h3>Score</h3><div id="secS" style="font-size:44px;text-align:center;color:#4caf50;">-</div></div></div></div>
<div class="tc" id="t-ai"><div class="panel"><h3>🤖 AI Analysis</h3><div id="aiC"><p style="color:#555;">Capture packets first</p></div></div></div>
<div class="tc" id="t-threats"><div class="panel"><h3>🛡 Threat Report</h3><div id="thC"><p style="color:#555;">Capture packets first</p></div></div></div>
<div class="tc" id="t-diag"><div class="panel"><h3>🔧 Diagnostics</h3><div id="diC"><p style="color:#555;">Click Diagnostics button</p></div></div></div>
</div>{% endif %}{% endif %}
<script>
let ut;function start(){fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({count:parseInt(document.getElementById('pktC').value)||50,filter:document.getElementById('filt').value||''})}).then(r=>r.json()).then(d=>{if(d.status==='ok'){document.getElementById('bStart').disabled=true;document.getElementById('bStop').disabled=false;document.getElementById('dot').className='ld ln';ut=setInterval(up,1000);}});}
function stop(){fetch('/api/stop',{method:'POST'}).then(r=>r.json()).then(d=>{document.getElementById('bStart').disabled=false;document.getElementById('bStop').disabled=true;document.getElementById('dot').className='ld lf';clearInterval(ut);up();});}
function exportPCAP(){fetch('/api/export').then(r=>r.json()).then(d=>{alert(d.file||'No data');});}
function runDiag(){fetch('/api/diag').then(r=>r.json()).then(d=>{let h='';if(d.avg)h+='<p>📡 Latency: <b>'+d.avg+'ms</b></p>';if(d.dns)h+='<p>📖 DNS: <b>'+d.dns+'ms</b></p>';d.issues.forEach(i=>h+='<p style="color:#ff9800;">⚠ '+i+'</p>');d.recs.forEach(r=>h+='<p style="color:#00d4ff;">💡 '+r+'</p>');document.getElementById('diC').innerHTML=h;st('diag');});}
function showAI(){up();fetch('/api/ai').then(r=>r.json()).then(d=>{if(d.error){document.getElementById('aiC').innerHTML='<p style="color:#f44336;">Capture first!</p>';}else{let h='';d.summary.forEach(s=>h+='<p>• '+s+'</p>');d.findings.forEach(f=>h+='<p style="color:#ff9800;">• '+f+'</p>');d.recs.forEach(r=>h+='<p style="color:#00d4ff;">💡 '+r+'</p>');h+='<p style="margin-top:10px;">Score: <b style="color:'+(d.score>=7?'#4caf50':d.score>=4?'#ff9800':'#f44336')+'">'+d.score+'/10</b></p>';document.getElementById('aiC').innerHTML=h;}st('ai');});}
function showThreats(){up();fetch('/api/threats').then(r=>r.json()).then(d=>{if(d.total===undefined){document.getElementById('thC').innerHTML='<p style="color:#f44336;">Capture first!</p>';}else{let h='<p>Risk: <b>'+d.risk+'</b> | Threats: <b>'+d.total+'</b></p>';if(d.recs){h+='<p style="margin-top:8px;">Recommendations:</p>';d.recs.forEach(r=>h+='<p style="color:#00d4ff;">💡 '+r+'</p>');}document.getElementById('thC').innerHTML=h;}st('threats');});}
function genPDF(){fetch('/api/pdf').then(r=>r.json()).then(d=>{alert(d.file?'Report: '+d.file:'Capture first or install reportlab');});}
function up(){fetch('/api/stats').then(r=>r.json()).then(d=>{document.getElementById('cnt').innerText=d.total_count||0;document.getElementById('byt').innerText=((d.total_bytes||0)/1024).toFixed(1)+' KB';document.getElementById('dur').innerText=(d.duration||0)+'s';document.getElementById('pps').innerText=d.pps||0;
if(d.packets&&d.packets.length){let h='';d.packets.slice(-25).reverse().forEach(p=>{h+='<tr><td>#'+p.count+'</td><td>'+p.time+'</td><td class="'+p.protocol.toLowerCase()+'">'+p.protocol+'</td><td>'+p.src+'</td><td>'+p.dst+'</td><td>'+p.size+'B</td><td>'+(p.service||'-')+'</td></tr>';});document.getElementById('pBody').innerHTML=h;}
let t=d.total_count||1;let ph='';['TCP','UDP','ICMP'].forEach(p=>{let c=(d.protocols||{})[p]||0;let pct=(c/t*100).toFixed(1);ph+='<div class="bw"><div class="bl"><span>'+p+'</span><span>'+c+' ('+pct+'%)</span></div><div class="b"><div class="bf" style="width:'+pct+'%;background:'+(p==='TCP'?'#4caf50':p==='UDP'?'#ff9800':'#e91e63')+'"></div></div></div>';});document.getElementById('pBars').innerHTML=ph;
if(d.alerts&&d.alerts.length)document.getElementById('aBox').innerHTML=d.alerts.map(a=>'<div class="alr aw">'+a+'</div>').join('');
if(d.top_ips&&d.top_ips.length)document.getElementById('tIPs').innerHTML=d.top_ips.map(([ip,c])=>'<div style="padding:2px 0;border-bottom:1px solid #1a2535;"><b>'+ip+'</b>: '+c+'</div>').join('');
if(d.services){let s='';Object.entries(d.services).sort((a,b)=>b[1]-a[1]).slice(0,8).forEach(([sv,c])=>{if(sv)s+='<div style="display:flex;justify-content:space-between;">'+sv+': <b>'+c+'</b></div>';});document.getElementById('tSvc').innerHTML=s||'No services';}});}
function st(t){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tc').forEach(x=>x.classList.remove('active'));document.getElementById('t-'+t).classList.add('active');event.target.classList.add('active');}
setInterval(()=>{fetch('/api/stats').then(r=>r.json()).then(d=>{if(!d.is_running){document.getElementById('bStart').disabled=false;document.getElementById('bStop').disabled=true;document.getElementById('dot').className='ld lf';}});},3000);
</script></body></html>'''

# ==================== ROUTES ====================
@app.route('/')
def index():
    if 'user' not in session: return redirect('/login')
    return render_template_string(HTML,session=session)

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form.get('username','').strip();p=request.form.get('password','')
        ok,msg,role=auth.check(u,p)
        if ok:
            session['user']=u;session['role']=role
            db.log(u,"login");return redirect('/')
        return render_template_string(HTML,session={},msg=msg,mt='err')
    return render_template_string(HTML,session={})

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        u=request.form.get('username','').strip();p=request.form.get('password','')
        c=request.form.get('confirm','');e=request.form.get('email','');sa=request.form.get('sa',DEFAULT_ANSWER)
        if p!=c: return render_template_string(HTML,session={},msg="Passwords don't match",mt='err',page='register')
        ok,msg=auth.add(u,p,"user",e,sa)
        if ok: return render_template_string(HTML,session={},msg="Created! Please login.",mt='ok')
        return render_template_string(HTML,session={},msg=msg,mt='err',page='register')
    return render_template_string(HTML,session={},page='register')

@app.route('/forgot',methods=['GET','POST'])
def forgot():
    if request.method=='POST':
        u=request.form.get('username','').strip();sa=request.form.get('sa','').strip()
        np=request.form.get('new_password','');cp=request.form.get('confirm','')
        if np!=cp: return render_template_string(HTML,session={},msg="Don't match",mt='err',page='forgot')
        ok,msg=auth.reset_pw(u,sa,np)
        if ok: return render_template_string(HTML,session={},msg=msg,mt='ok')
        return render_template_string(HTML,session={},msg=msg,mt='err',page='forgot')
    return render_template_string(HTML,session={},page='forgot')

@app.route('/guest')
def guest():
    session['user']='guest';session['role']='guest';return redirect('/')

@app.route('/logout')
def logout():
    session.clear();return redirect('/login')

@app.route('/admin')
def admin():
    if session.get('role')!='admin': return redirect('/')
    return render_template_string(HTML,session=session,admin_panel=True,ulist=auth.all_users())

@app.route('/admin/cpw',methods=['POST'])
def admin_cpw():
    if session.get('role')!='admin': return redirect('/')
    old=request.form.get('old','');new=request.form.get('new','');cp=request.form.get('confirm','')
    if new!=cp: return render_template_string(HTML,session=session,admin_panel=True,ulist=auth.all_users(),am="Don't match",amt='err')
    ok,msg=auth.change_pw(session['user'],old,new)
    return render_template_string(HTML,session=session,admin_panel=True,ulist=auth.all_users(),am=msg,amt='ok' if ok else 'err')

@app.route('/admin/del',methods=['POST'])
def admin_del():
    if session.get('role')!='admin': return redirect('/')
    target=request.form.get('target','')
    ok,msg=auth.delete_user(session['user'],target)
    return render_template_string(HTML,session=session,admin_panel=True,ulist=auth.all_users(),am=msg,amt='ok' if ok else 'err')

@app.route('/api/start',methods=['POST'])
def api_start():
    d=request.json;capture.start(d.get('count',50),d.get('filter',''));return jsonify({"status":"ok"})

@app.route('/api/stop',methods=['POST'])
def api_stop():
    capture.stop();return jsonify({"status":"ok"})

@app.route('/api/stats')
def api_stats():
    return jsonify(capture.stats())

@app.route('/api/export')
def api_export():
    fn=capture.export();return jsonify({"file":fn})

@app.route('/api/ai')
def api_ai():
    return jsonify(capture.ai())

@app.route('/api/threats')
def api_threats():
    return jsonify(capture.threat_report())

@app.route('/api/pdf')
def api_pdf():
    s=capture.stats();tr=capture.threat_report()
    fn=pdfgen.generate(s,tr);return jsonify({"file":fn})

@app.route('/api/diag')
def api_diag():
    return jsonify(diagnostics())
@app.route('/download/<filename>')
def download_file(filename):
    return send_file(f"reports/{filename}", as_attachment=True)

if __name__=='__main__':
    print("\n"+"="*55)
    print("  NETWORK SNIFFER PRO v10.0")
    print("  http://localhost:5000")
    print("  admin / Admin@123")
    print("="*55+"\n")
    app.run(debug=True,host='0.0.0.0',port=5000)