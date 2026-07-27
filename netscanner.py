#!/usr/bin/env python3
"""
NetScanner Pro v3.0 — Advanced Standalone Network Scanner
Zero external dependencies | Python 3.8+ stdlib only
TCP · SYN · SSL/TLS · HTTP · DNS · Traceroute · HTML Report · Curses TUI
Usage: python3 netscanner.py [OPTIONS] TARGET
       python3 netscanner.py --tui 192.168.1.0/24
"""
import socket, ssl, struct, sys, os, time, threading, ipaddress, shutil, signal
import argparse, subprocess, re, json, select, random, textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict
import http.client

# ══════════════════════════════════════════════════════════
# COLORS
# ══════════════════════════════════════════════════════════
class C:
    _t = sys.stdout.isatty()
    R='\033[91m'if _t else''; G='\033[92m'if _t else''
    Y='\033[93m'if _t else''; B='\033[94m'if _t else''
    M='\033[95m'if _t else''; CY='\033[96m'if _t else''
    W='\033[97m'if _t else''; DIM='\033[2m'if _t else''
    BO='\033[1m'if _t else''; N='\033[0m'if _t else''

# ══════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════
PORT_NAMES = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',
    80:'HTTP',110:'POP3',111:'RPC',135:'MSRPC',139:'NetBIOS',
    143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',445:'SMB',
    465:'SMTPS',514:'Syslog',587:'Submission',631:'IPP',
    636:'LDAPS',873:'rsync',993:'IMAPS',995:'POP3S',
    1080:'SOCKS',1194:'OpenVPN',1433:'MSSQL',1521:'Oracle',
    1723:'PPTP',2049:'NFS',2181:'Zookeeper',2375:'Docker-API',
    2376:'Docker-TLS',3000:'HTTP-alt',3306:'MySQL',3389:'RDP',
    4444:'Backdoor?',5432:'PostgreSQL',5672:'RabbitMQ',
    5900:'VNC',5984:'CouchDB',6379:'Redis',6443:'K8s-API',
    6667:'IRC',7001:'WebLogic',8080:'HTTP-alt',8443:'HTTPS-alt',
    8888:'Jupyter?',9000:'HTTP-alt',9092:'Kafka',
    9200:'Elasticsearch',9300:'Elasticsearch',10000:'Webmin',
    11211:'Memcached',27017:'MongoDB',50070:'Hadoop',61616:'ActiveMQ',
}

SEC_HEADERS = [
    'Strict-Transport-Security','Content-Security-Policy',
    'X-Frame-Options','X-Content-Type-Options','X-XSS-Protection',
    'Referrer-Policy','Permissions-Policy','Cross-Origin-Opener-Policy',
]

VULN_DB = {
    21: ('CRIT','FTP',          'Anonymous login possible; credentials en clair'),
    23: ('CRIT','Telnet',       'Protocole en clair — remplacer par SSH'),
    4444:('CRIT','Backdoor?',   'Port C2/backdoor courant — vérifier'),
    6379:('CRIT','Redis',       'Pas d\'auth par défaut — RCE via config write'),
    9200:('CRIT','Elasticsearch','Pas d\'auth par défaut — exfiltration données'),
    27017:('CRIT','MongoDB',    'Pas d\'auth par défaut — accès total'),
    2375:('CRIT','Docker-API',  'Docker non authentifié — évasion container triviale'),
    445: ('HIGH','SMB',         'EternalBlue MS17-010; vérifier SMB signing'),
    3389:('HIGH','RDP',         'BlueKeep CVE-2019-0708; imposer NLA'),
    5900:('HIGH','VNC',         'Auth faible fréquente — forcer mot de passe fort'),
    7001:('HIGH','WebLogic',    'CVE-2020-14882 RCE non authentifié'),
    10000:('HIGH','Webmin',     'CVE-2019-15107 RCE non authentifié'),
    11211:('HIGH','Memcached',  'Amplification DDoS UDP; exposition données'),
    22:  ('INFO','SSH',         'Vérifier: root login, auth par clé, version'),
    25:  ('MED', 'SMTP',        'Vérifier open relay, commandes VRFY/EXPN'),
    1433:('MED', 'MSSQL',       'Vérifier compte SA, xp_cmdshell'),
    5432:('MED', 'PostgreSQL',  'Vérifier pg_hba.conf, trust auth'),
    3306:('MED', 'MySQL',       'Vérifier root distant, skip-networking'),
    8888:('MED', 'Jupyter?',    'Jupyter sans auth expose exécution de code'),
}

OS_TTL = [(0,64,'Linux/Unix/Android'),(65,128,'Windows'),(129,255,'Cisco/BSD')]

# ══════════════════════════════════════════════════════════
# SHARED STATE (for TUI)
# ══════════════════════════════════════════════════════════
class ScanState:
    def __init__(self):
        self.lock       = threading.Lock()
        self.results    = []          # list of host dicts
        self.log        = []          # log lines
        self.current    = ''          # current host being scanned
        self.progress   = 0           # ports scanned
        self.total      = 0           # total ports to scan
        self.done       = False
        self.start      = time.time()

    def push_log(self, msg):
        with self.lock:
            ts = datetime.now().strftime('%H:%M:%S')
            self.log.append(f'[{ts}] {msg}')
            if len(self.log) > 200:
                self.log.pop(0)

# ══════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════
def print_banner():
    print(f"""{C.G}{C.BO}
 ███╗   ██╗███████╗████████╗    ██████╗ ██████╗  ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔═══██╗
 ██╔██╗ ██║█████╗     ██║       ██████╔╝██████╔╝██║   ██║
 ██║╚██╗██║██╔══╝     ██║       ██╔═══╝ ██╔══██╗██║   ██║
 ██║ ╚████║███████╗   ██║       ██║     ██║  ██║╚██████╔╝
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚═════╝
{C.N}  {C.CY}NetScanner Pro v3.0 — All-in-One Standalone Scanner{C.N}
  {C.DIM}TCP·SYN·SSL·HTTP·DNS·Traceroute·HTML·TUI — Zero deps{C.N}
""")

# ══════════════════════════════════════════════════════════
# HOST DISCOVERY
# ══════════════════════════════════════════════════════════
class HostDiscovery:
    def __init__(self, timeout=1.0):
        self.timeout = timeout

    def ping(self, ip):
        param = ['-n','1','-w',str(int(self.timeout*1000))] if sys.platform=='win32' \
                else ['-c','1','-W',str(int(self.timeout))]
        try:
            r = subprocess.run(['ping']+param+[str(ip)],
                               capture_output=True, timeout=self.timeout+1)
            if r.returncode == 0:
                out = r.stdout.decode(errors='replace')
                m = re.search(r'ttl[=\s]+(\d+)', out, re.I)
                ttl = int(m.group(1)) if m else None
                return str(ip), True, ttl
        except Exception:
            pass
        return str(ip), False, None

    def tcp_ping(self, ip, port=80):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            ok = s.connect_ex((str(ip), port)) == 0
            s.close()
            return str(ip), ok, None
        except Exception:
            return str(ip), False, None

    def scan_network(self, network, workers=200, state=None):
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts()) or [ipaddress.ip_address(network)]
        except ValueError:
            hosts = [ipaddress.ip_address(network)]

        live, lock, done = [], threading.Lock(), [0]
        total = len(hosts)

        def probe(ip):
            result = self.ping(str(ip))
            if not result[1]:
                result = self.tcp_ping(str(ip))
            with lock:
                done[0] += 1
                if state:
                    state.push_log(f'Ping {ip}: {"alive" if result[1] else "dead"}')
                else:
                    pct = int(done[0]/total*40)
                    print(f'\r  {C.DIM}[{"█"*pct}{"░"*(40-pct)}] {done[0]}/{total}{C.N}',
                          end='', flush=True)
            return result

        with ThreadPoolExecutor(max_workers=min(workers,total,256)) as ex:
            futures = {ex.submit(probe, ip): ip for ip in hosts}
            for f in as_completed(futures):
                ip, alive, ttl = f.result()
                if alive:
                    os_g = next((n for lo,hi,n in OS_TTL if ttl and lo<=ttl<=hi), 'Unknown')
                    try: hn = socket.gethostbyaddr(ip)[0]
                    except: hn = ''
                    with lock:
                        live.append({'ip':ip,'hostname':hn,'ttl':ttl,'os_guess':os_g})
        if not state:
            print()
        return sorted(live, key=lambda x: socket.inet_aton(x['ip']))

# ══════════════════════════════════════════════════════════
# TCP SCANNER
# ══════════════════════════════════════════════════════════
class TCPScanner:
    def __init__(self, timeout=1.0):
        self.timeout = timeout

    def scan_port(self, ip, port):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            if s.connect_ex((ip, port)) == 0:
                banner = self._grab(s, port)
                s.close()
                return {'port':port,'proto':'tcp','state':'open',
                        'service':self._svc(port,banner),'banner':banner,'method':'CONNECT'}
            s.close()
        except Exception:
            pass
        return None

    def _grab(self, sock, port):
        try:
            probes = {
                80:b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
                8080:b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
                443:b'HEAD / HTTP/1.0\r\n\r\n',
                6379:b'PING\r\n',
                11211:b'stats\r\n',
                21:b'',22:b'',25:b'',110:b'',143:b'',
            }
            if port in probes and probes[port]:
                sock.send(probes[port])
            rdy = select.select([sock],[],[],self.timeout)
            if rdy[0]:
                d = sock.recv(1024)
                return ' '.join(d.decode('utf-8',errors='replace')[:200].split())
        except Exception:
            pass
        return ''

    def _svc(self, port, banner):
        if banner:
            b = banner.lower()
            if 'ssh' in b: return 'SSH'
            if 'ftp' in b: return 'FTP'
            if 'smtp' in b or '220 ' in b: return 'SMTP'
            if 'mysql' in b or 'mariadb' in b: return 'MySQL'
            if '+pong' in b: return 'Redis'
            if 'http' in b or 'html' in b:
                return 'HTTPS' if port in (443,8443) else 'HTTP'
        return PORT_NAMES.get(port, f'unknown')

    def scan(self, ip, ports, workers=400, state=None):
        results, lock = [], threading.Lock()
        def task(p):
            r = self.scan_port(ip, p)
            if state:
                with lock:
                    state.progress += 1
            return r
        with ThreadPoolExecutor(max_workers=min(workers,len(ports))) as ex:
            for r in as_completed({ex.submit(task,p):p for p in ports}):
                res = r.result()
                if res:
                    with lock:
                        results.append(res)
        return sorted(results, key=lambda x: x['port'])

# ══════════════════════════════════════════════════════════
# SYN SCANNER (root required)
# ══════════════════════════════════════════════════════════
class SYNScanner:
    def __init__(self, timeout=2.0):
        self.timeout  = timeout
        self._results = {}
        self._lock    = threading.Lock()
        self._stop    = threading.Event()

    def _cksum(self, data):
        s = sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data)-1,2))
        if len(data)%2: s += data[-1]<<8
        s = (s>>16)+(s&0xffff); s += s>>16
        return ~s & 0xffff

    def _build(self, sip, dip, sport, dport):
        seq = random.randint(0, 2**32-1)
        # TCP SYN header (no checksum yet)
        tcp = struct.pack('!HHLLBBHHH', sport, dport, seq, 0,
                          5<<4, 0x002, 65535, 0, 0)
        # Pseudo header
        pseudo = struct.pack('!4s4sBBH',
                             socket.inet_aton(sip), socket.inet_aton(dip),
                             0, socket.IPPROTO_TCP, len(tcp))
        chk = self._cksum(pseudo+tcp)
        tcp = struct.pack('!HHLLBBHHH', sport, dport, seq, 0,
                          5<<4, 0x002, 65535, chk, 0)
        # IP header
        ip = struct.pack('!BBHHHBBH4s4s',
                         0x45, 0, 40, random.randint(1,65535), 0,
                         64, socket.IPPROTO_TCP, 0,
                         socket.inet_aton(sip), socket.inet_aton(dip))
        return ip+tcp

    def _recv_loop(self, sock, my_sports):
        deadline = time.time()+self.timeout+1
        while time.time()<deadline and not self._stop.is_set():
            try:
                rdy = select.select([sock],[],[],0.1)
                if not rdy[0]: continue
                data,_ = sock.recvfrom(65535)
                if len(data)<40: continue
                ihl = (data[0]&0xf)*4
                tcp = data[ihl:]
                if len(tcp)<14: continue
                sp,dp,_,_,of = struct.unpack('!HHLLH',tcp[:14])
                flags = of & 0x3f
                if dp not in my_sports: continue
                with self._lock:
                    if flags==0x12: self._results[dp]='open'
                    elif flags&0x4:  self._results[dp]='closed'
            except Exception:
                break

    def scan(self, dst_ip, ports):
        try:
            tx = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
            tx.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
            rx = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
            rx.settimeout(1.0)
        except PermissionError:
            return None  # Signal: not root

        # Get source IP
        try:
            t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            t.connect((dst_ip,80)); sip=t.getsockname()[0]; t.close()
        except: sip='0.0.0.0'

        sport_map = {random.randint(49152,65535):p for p in ports}
        my_sports = set(sport_map.keys())

        rt = threading.Thread(target=self._recv_loop,args=(rx,my_sports),daemon=True)
        rt.start()

        for sp,dp in sport_map.items():
            try:
                pkt = self._build(sip,dst_ip,sp,dp)
                tx.sendto(pkt,(dst_ip,0))
                time.sleep(0.0005)
            except Exception:
                pass

        time.sleep(self.timeout)
        self._stop.set()
        rt.join(timeout=2)
        tx.close(); rx.close()

        results=[]
        for sp,dp in sport_map.items():
            if self._results.get(sp)=='open':
                results.append({'port':dp,'proto':'tcp','state':'open',
                                'service':PORT_NAMES.get(dp,'unknown'),
                                'banner':'','method':'SYN'})
        return sorted(results,key=lambda x:x['port'])

# ══════════════════════════════════════════════════════════
# SSL / TLS INSPECTOR
# ══════════════════════════════════════════════════════════
class SSLInspector:
    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def inspect(self, host, port=443):
        res = {'host':host,'port':port,'enabled':False,
               'version':'','cipher':'','bits':0,
               'subject':{},'issuer':{},'san':[],
               'expiry':'','days_left':None,'self_signed':False,
               'error':''}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_OPTIONAL
        try:
            raw = socket.create_connection((host,port),timeout=self.timeout)
            with ctx.wrap_socket(raw,server_hostname=host) as ss:
                cert   = ss.getpeercert()
                cipher = ss.cipher()
                ver    = ss.version()
                res['enabled'] = True
                res['version'] = ver or ''
                res['cipher']  = cipher[0] if cipher else ''
                res['bits']    = cipher[2] if cipher else 0
                # Subject / Issuer
                for field,key in [('subject','subject'),('issuer','issuer')]:
                    for pair in cert.get(key,()):
                        for k,v in pair: res[field][k]=v
                # SAN
                for kind,val in cert.get('subjectAltName',()):
                    if kind=='DNS': res['san'].append(val)
                # Expiry
                nb = cert.get('notAfter','')
                if nb:
                    try:
                        exp = datetime.strptime(nb,'%b %d %H:%M:%S %Y %Z')
                        res['expiry']    = exp.strftime('%Y-%m-%d')
                        res['days_left'] = (exp-datetime.utcnow()).days
                    except Exception:
                        res['expiry'] = nb
                # Self-signed
                res['self_signed'] = res['subject'].get('organizationName') == \
                                     res['issuer'].get('organizationName') and \
                                     res['subject'].get('commonName') == \
                                     res['issuer'].get('commonName')
        except ssl.SSLError as e:
            res['error'] = f'SSL: {e}'
        except Exception as e:
            res['error'] = str(e)
        return res

# ══════════════════════════════════════════════════════════
# HTTP SECURITY ANALYZER
# ══════════════════════════════════════════════════════════
class HTTPAnalyzer:
    def __init__(self, timeout=5.0):
        self.timeout = timeout
        self.UA = 'Mozilla/5.0 (compatible; NetScannerPro/3.0)'

    def analyze(self, host, port=80, use_tls=False):
        res = {'url':'','status':0,'server':'','powered_by':'',
               'headers':{},'sec_headers':{},'missing_sec':[],
               'redirects_https':False,'tech':[],'paths':{},'error':''}
        scheme = 'https' if use_tls else 'http'
        res['url'] = f'{scheme}://{host}:{port}/'
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host,port,timeout=self.timeout,context=ctx)
            else:
                conn = http.client.HTTPConnection(host,port,timeout=self.timeout)
            conn.request('GET','/',headers={'User-Agent':self.UA,'Host':host})
            r = conn.getresponse()
            res['status'] = r.status
            hdrs = {k.lower():v for k,v in r.getheaders()}
            res['headers'] = hdrs
            res['server']     = hdrs.get('server','')
            res['powered_by'] = hdrs.get('x-powered-by','')
            # Security headers
            for sh in SEC_HEADERS:
                val = hdrs.get(sh.lower(),'')
                res['sec_headers'][sh] = val
                if not val: res['missing_sec'].append(sh)
            # HTTPS redirect
            if r.status in (301,302,307,308):
                loc = hdrs.get('location','')
                res['redirects_https'] = loc.startswith('https://')
            # Tech detection
            tech = []
            srv = (res['server']+res['powered_by']).lower()
            if 'nginx'    in srv: tech.append('Nginx')
            if 'apache'   in srv: tech.append('Apache')
            if 'iis'      in srv: tech.append('IIS')
            if 'php'      in srv: tech.append('PHP')
            if 'express'  in srv: tech.append('Express.js')
            if 'django'   in srv: tech.append('Django')
            if 'gunicorn' in srv: tech.append('Gunicorn')
            res['tech'] = tech
            # Probe sensitive paths
            for path in ['/.git/config','/robots.txt','/.env','/admin','/wp-login.php','/phpmyadmin']:
                try:
                    conn2 = http.client.HTTPConnection(host,port,timeout=2) if not use_tls \
                            else http.client.HTTPSConnection(host,port,timeout=2,context=ctx if use_tls else None)
                    conn2.request('GET',path,headers={'User-Agent':self.UA,'Host':host})
                    r2 = conn2.getresponse()
                    res['paths'][path] = r2.status
                    conn2.close()
                except Exception:
                    pass
            conn.close()
        except Exception as e:
            res['error'] = str(e)
        return res

# ══════════════════════════════════════════════════════════
# DNS RECONNAISSANCE
# ══════════════════════════════════════════════════════════
class DNSRecon:
    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def _dig(self, domain, rtype):
        """Run dig or nslookup for record type."""
        for cmd in [['dig','+short',rtype,domain],
                    ['nslookup',f'-type={rtype}',domain]]:
            if shutil.which(cmd[0]):
                try:
                    r = subprocess.run(cmd,capture_output=True,timeout=self.timeout,text=True)
                    return [l.strip() for l in r.stdout.splitlines() if l.strip() and not l.startswith(';')]
                except Exception:
                    pass
        return []

    def recon(self, host):
        res = {'target':host,'a':[],'aaaa':[],'ptr':'',
               'mx':[],'ns':[],'txt':[],'cname':[],'zone_transfer':'',
               'subdomains':[],'error':''}
        # A / AAAA
        try:
            for ai in socket.getaddrinfo(host,None):
                if ai[0]==socket.AF_INET  and ai[4][0] not in res['a']:
                    res['a'].append(ai[4][0])
                if ai[0]==socket.AF_INET6 and ai[4][0] not in res['aaaa']:
                    res['aaaa'].append(ai[4][0])
        except Exception as e: res['error']=str(e)
        # PTR (reverse)
        for ip in res['a'][:1]:
            try: res['ptr']=socket.gethostbyaddr(ip)[0]
            except: pass
        # MX NS TXT CNAME
        domain = host if '.' in host else host
        res['mx']    = self._dig(domain,'MX')
        res['ns']    = self._dig(domain,'NS')
        res['txt']   = self._dig(domain,'TXT')
        res['cname'] = self._dig(domain,'CNAME')
        # Zone transfer attempt (informational)
        for ns in res['ns'][:2]:
            ns = ns.rstrip('.')
            zt = self._dig(domain, f'AXFR @{ns}')
            if zt and len(zt)>2:
                res['zone_transfer'] = f'SUCCESS via {ns} ({len(zt)} records)'
                break
        # Common subdomains
        common_sub = ['www','mail','ftp','vpn','api','dev','staging',
                      'admin','remote','portal','cloud','ns1','ns2']
        found_subs = []
        for sub in common_sub:
            try:
                fqdn = f'{sub}.{domain}'
                socket.setdefaulttimeout(1)
                socket.gethostbyname(fqdn)
                found_subs.append(fqdn)
            except Exception: pass
        res['subdomains'] = found_subs
        return res

# ══════════════════════════════════════════════════════════
# TRACEROUTE
# ══════════════════════════════════════════════════════════
class Tracer:
    def __init__(self, max_hops=20, timeout=2.0):
        self.max_hops = max_hops
        self.timeout  = timeout

    def trace(self, host):
        hops = []
        # Try system traceroute first
        cmd = 'traceroute' if sys.platform!='win32' else 'tracert'
        if shutil.which(cmd):
            args = [cmd,'-m',str(self.max_hops),'-n',host] if sys.platform!='win32' \
                   else [cmd,'-h',str(self.max_hops),host]
            try:
                r = subprocess.run(args,capture_output=True,
                                   timeout=self.timeout*self.max_hops+5,text=True)
                for line in r.stdout.splitlines()[1:]:
                    line = line.strip()
                    if not line: continue
                    parts  = line.split()
                    if not parts or not parts[0].isdigit(): continue
                    hop_n  = int(parts[0])
                    ips    = [p for p in parts if re.match(r'\d+\.\d+\.\d+\.\d+',p)]
                    rtts   = re.findall(r'(\d+\.?\d*)\s*ms',line)
                    avg_ms = round(sum(float(x) for x in rtts)/len(rtts),2) if rtts else None
                    ip     = ips[0] if ips else '*'
                    try: hn = socket.gethostbyaddr(ip)[0] if ip!='*' else ''
                    except: hn=''
                    hops.append({'hop':hop_n,'ip':ip,'hostname':hn,'rtt_ms':avg_ms})
                return hops
            except Exception:
                pass
        # Fallback: ping with TTL
        return self._ping_ttl(host)

    def _ping_ttl(self, host):
        hops=[]
        for ttl in range(1,self.max_hops+1):
            if sys.platform=='darwin':
                cmd=['ping','-c','1','-m',str(ttl),'-W','1000',host]
            elif sys.platform=='win32':
                cmd=['ping','-n','1','-i',str(ttl),'-w','1000',host]
            else:
                cmd=['ping','-c','1','-t',str(ttl),'-W','1',host]
            try:
                r=subprocess.run(cmd,capture_output=True,timeout=3,text=True)
                out=r.stdout+r.stderr
                rtt=re.search(r'time[=<](\d+\.?\d*)',out)
                reached=(r.returncode==0)
                hops.append({'hop':ttl,'ip':host if reached else '?',
                             'hostname':'','rtt_ms':float(rtt.group(1)) if rtt else None})
                if reached: break
            except Exception:
                hops.append({'hop':ttl,'ip':'*','hostname':'','rtt_ms':None})
        return hops

# ══════════════════════════════════════════════════════════
# OS FINGERPRINTING
# ══════════════════════════════════════════════════════════
class OSFingerprint:
    def __init__(self, timeout=2.0):
        self.timeout=timeout

    def fingerprint(self, host_info, open_ports, banners):
        guess  = host_info.get('os_guess','Unknown')
        conf   = 30 if guess!='Unknown' else 0
        method = [f'TTL({guess})'] if guess!='Unknown' else []
        port_set = set(p['port'] for p in open_ports)

        # Banner analysis
        all_banners = ' '.join(banners.values()).lower()
        for kw,os_name in [
            ('ubuntu','Linux (Ubuntu)'),('debian','Linux (Debian)'),
            ('centos','Linux (CentOS)'),('red hat','Linux (RHEL)'),
            ('windows','Windows'),('microsoft','Windows'),('iis','Windows'),
            ('freebsd','FreeBSD'),('openbsd','OpenBSD'),('cisco','Cisco IOS'),
        ]:
            if kw in all_banners:
                guess=os_name; conf=75; method.append(f'banner({os_name})')
                break

        # Port heuristics
        if {135,139,445,3389}&port_set and conf<70:
            guess='Windows'; conf=65; method.append('ports(Win)')
        elif {22,111,2049}&port_set and 3389 not in port_set and conf<65:
            guess='Linux/Unix'; conf=55; method.append('ports(Linux)')
        elif {23,161}&port_set and conf<50:
            guess='Network Device'; conf=45; method.append('ports(NetDev)')

        return {'guess':guess,'confidence':min(conf,95),'methods':method}

# ══════════════════════════════════════════════════════════
# PORT LIST BUILDER
# ══════════════════════════════════════════════════════════
def build_port_list(spec):
    if spec=='all':    return list(range(1,65536))
    if spec=='top100': return sorted(PORT_NAMES.keys())[:100]
    if spec=='top1000':
        extra=list(range(1,1025))+[8000,8001,8008,8081,8082,8083,8084,
              8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,
              8096,8097,8099,8100,8200,8300,8400,8500,8600,8700,8800,
              8900,9001,9002,9003,9080,9090,9100,9101,9102]
        return sorted(set(list(PORT_NAMES.keys())+extra))[:1000]
    ports=set()
    for part in spec.split(','):
        part=part.strip()
        if '-' in part:
            a,b=part.split('-',1); ports.update(range(int(a),int(b)+1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)

# ══════════════════════════════════════════════════════════
# HTML REPORTER
# ══════════════════════════════════════════════════════════
class HTMLReporter:
    def generate(self, results, filename):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_open = sum(len(r.get('ports',[])) for r in results)
        total_crit = sum(
            sum(1 for p in r.get('ports',[])
                if VULN_DB.get(p['port'],('','',''))[0]=='CRIT')
            for r in results)

        # SVG bar chart for services
        svc_count = defaultdict(int)
        for r in results:
            for p in r.get('ports',[]):
                svc_count[p.get('service','unknown')] += 1
        top_svcs = sorted(svc_count.items(), key=lambda x:-x[1])[:10]
        chart_svg = self._bar_chart(top_svcs)

        hosts_html = '\n'.join(self._host_section(r) for r in results)

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScanner Pro — Rapport {now}</title>
<style>
:root{{--bg:#0a0a0f;--surf:#12121a;--surf2:#1a1a26;
      --text:#c0c0c0;--acc:#00ff88;--cr:#ff3333;
      --hi:#ff8800;--me:#ffcc00;--lo:#00cc44;--inf:#4488ff}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);
      font-family:'Consolas','Courier New',monospace;padding:20px}}
h1{{color:var(--acc);font-size:2em;margin-bottom:5px}}
h2{{color:var(--acc);border-bottom:1px solid #333;
    padding-bottom:8px;margin:20px 0 12px}}
h3{{color:var(--acc);margin-bottom:8px;font-size:1.1em}}
.container{{max-width:1400px;margin:0 auto}}
.header{{background:var(--surf);border:1px solid var(--acc);
         padding:25px;margin-bottom:25px;border-radius:10px;text-align:center}}
.classified{{background:var(--cr);color:#fff;text-align:center;
             padding:10px;margin-bottom:20px;font-weight:bold;
             border-radius:5px;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.7}}}}
.dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
            gap:15px;margin-bottom:25px}}
.card{{background:var(--surf);padding:18px;border-radius:8px;
       border-left:4px solid var(--acc)}}
.card.CRIT{{border-left-color:var(--cr)}}
.card.HIGH{{border-left-color:var(--hi)}}
.big-num{{font-size:2.5em;font-weight:bold;color:var(--acc)}}
.section{{background:var(--surf);padding:20px;margin-bottom:20px;border-radius:8px}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
th{{background:#000;color:var(--acc);padding:8px 12px;text-align:left}}
td{{padding:7px 12px;border-bottom:1px solid #1e1e2e}}
tr:hover td{{background:var(--surf2)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;
        font-size:.8em;font-weight:bold}}
.badge.CRIT{{background:rgba(255,51,51,.2);color:var(--cr)}}
.badge.HIGH{{background:rgba(255,136,0,.2);color:var(--hi)}}
.badge.MED{{background:rgba(255,204,0,.2);color:var(--me)}}
.badge.INFO{{background:rgba(68,136,255,.2);color:var(--inf)}}
.badge.open{{background:rgba(0,255,136,.2);color:var(--acc)}}
.badge.ok{{background:rgba(0,204,68,.2);color:var(--lo)}}
.badge.fail{{background:rgba(255,51,51,.2);color:var(--cr)}}
.badge.warn{{background:rgba(255,204,0,.2);color:var(--me)}}
.hop-bar{{display:flex;align-items:center;gap:8px;margin:4px 0}}
.hop-line{{height:3px;background:var(--acc);opacity:.6}}
pre{{background:#000;color:#0f0;padding:12px;border-radius:5px;
     overflow-x:auto;font-size:.82em;max-height:250px;overflow-y:auto;
     white-space:pre-wrap;word-break:break-all}}
.ssl-ok{{color:var(--lo)}} .ssl-warn{{color:var(--me)}} .ssl-bad{{color:var(--cr)}}
.footer{{text-align:center;color:#555;margin-top:30px;padding:20px;
         font-size:.8em;border-top:1px solid #222}}
</style>
</head>
<body>
<div class="container">
<div class="classified">⚠ RAPPORT CONFIDENTIEL — UTILISATION AUTORISÉE UNIQUEMENT ⚠</div>
<div class="header">
  <h1>🔍 NetScanner Pro v3.0</h1>
  <p style="color:#888">Rapport généré : {now}</p>
</div>
<div class="dashboard">
  <div class="card"><div class="big-num">{len(results)}</div><div>Hôtes scannés</div></div>
  <div class="card"><div class="big-num">{total_open}</div><div>Ports ouverts</div></div>
  <div class="card CRIT"><div class="big-num" style="color:var(--cr)">{total_crit}</div><div>Risques CRITIQUES</div></div>
</div>
<div class="section">
  <h2>📊 Distribution des services</h2>
  {chart_svg}
</div>
{hosts_html}
<div class="footer">
  NetScanner Pro v3.0 — Rapport de sécurité réseau — {now}
</div>
</div>
</body>
</html>"""
        with open(filename,'w',encoding='utf-8') as f:
            f.write(html)

    def _bar_chart(self, data):
        if not data: return '<p style="color:#555">Aucune donnée</p>'
        max_v = max(v for _,v in data) or 1
        W,H,bw = 600,200,40
        bars,x = '',20
        for svc,cnt in data:
            bh = int(cnt/max_v*(H-40))
            col = '#00ff88'
            bars += f'<rect x="{x}" y="{H-bh-30}" width="{bw-4}" height="{bh}" fill="{col}" opacity=".8"/>'
            bars += f'<text x="{x+bw//2-2}" y="{H-10}" fill="#888" font-size="9" text-anchor="middle">{svc[:8]}</text>'
            bars += f'<text x="{x+bw//2-2}" y="{H-bh-35}" fill="{col}" font-size="10" text-anchor="middle">{cnt}</text>'
            x+=bw+5
        total_w=x+20
        return f'<svg viewBox="0 0 {total_w} {H+10}" xmlns="http://www.w3.org/2000/svg" style="max-width:100%">{bars}</svg>'

    def _host_section(self, r):
        ip=r.get('ip','?'); hn=r.get('hostname','')
        os_g=r.get('os',{}).get('guess','?')
        os_c=r.get('os',{}).get('confidence',0)
        ports=r.get('ports',[])
        ssl_i=r.get('ssl',{})
        http_i=r.get('http',{})
        dns_i=r.get('dns',{})
        trace=r.get('trace',[])
        vulns=r.get('vulns',[])

        # Ports table
        port_rows=''
        for p in ports:
            v=VULN_DB.get(p['port'])
            badge=f'<span class="badge {v[0]}">{v[0]}</span>' if v else ''
            port_rows+=f'''<tr>
              <td>{p["port"]}</td><td>{p["proto"]}</td>
              <td><span class="badge open">open</span></td>
              <td>{p.get("service","?")}</td>
              <td style="color:#888;font-size:.85em">{p.get("banner","")[:60]}</td>
              <td>{badge}</td></tr>'''

        # SSL section
        ssl_html=''
        if ssl_i.get('enabled'):
            exp_cls='ssl-ok' if (ssl_i.get('days_left') or 0)>30 else 'ssl-bad'
            ss='✓' if not ssl_i.get('self_signed') else '⚠ Self-signed'
            ssl_html=f'''<div class="section">
            <h3>🔐 SSL/TLS — {ip}:{ssl_i.get("port",443)}</h3>
            <table><tr><th>Champ</th><th>Valeur</th></tr>
            <tr><td>Version</td><td>{ssl_i.get("version","")}</td></tr>
            <tr><td>Cipher</td><td>{ssl_i.get("cipher","")} ({ssl_i.get("bits","")} bits)</td></tr>
            <tr><td>Expiry</td><td class="{exp_cls}">{ssl_i.get("expiry","")} ({ssl_i.get("days_left","?")} jours)</td></tr>
            <tr><td>CN</td><td>{ssl_i.get("subject",{}).get("commonName","")}</td></tr>
            <tr><td>Issuer</td><td>{ssl_i.get("issuer",{}).get("organizationName","")}</td></tr>
            <tr><td>SAN</td><td>{", ".join(ssl_i.get("san",[])[:8])}</td></tr>
            <tr><td>Self-signed</td><td>{ss}</td></tr>
            </table></div>'''

        # HTTP section
        http_html=''
        if http_i.get('status'):
            sh_rows=''
            for sh in SEC_HEADERS:
                present=bool(http_i.get('sec_headers',{}).get(sh))
                cls='ok' if present else 'fail'
                icon='✓' if present else '✗'
                sh_rows+=f'<tr><td>{sh}</td><td><span class="badge {cls}">{icon}</span></td></tr>'
            paths_rows=''
            for path,code in http_i.get('paths',{}).items():
                cls='fail' if code==200 else 'ok'
                paths_rows+=f'<tr><td>{path}</td><td><span class="badge {cls}">{code}</span></td></tr>'
            http_html=f'''<div class="section">
            <h3>🌐 HTTP — {http_i.get("url","")}</h3>
            <p>Status: <b>{http_i.get("status","")}</b> | Server: <b>{http_i.get("server","")}</b>
               | Tech: <b>{", ".join(http_i.get("tech",[]) or ["?"])}</b></p>
            <h3 style="margin-top:15px">Security Headers</h3>
            <table><tr><th>Header</th><th>Présent</th></tr>{sh_rows}</table>
            {"<h3 style='margin-top:15px'>Chemins sensibles</h3><table><tr><th>Path</th><th>Code</th></tr>"+paths_rows+"</table>" if paths_rows else ""}
            </div>'''

        # DNS section
        dns_html=''
        if dns_i.get('a') or dns_i.get('mx'):
            zt=dns_i.get('zone_transfer','')
            zt_badge=f'<span class="badge CRIT">ZONE TRANSFER: {zt}</span>' if zt else ''
            subs=', '.join(dns_i.get('subdomains',[])[:10]) or 'Aucun trouvé'
            dns_html=f'''<div class="section">
            <h3>🌍 DNS — {dns_i.get("target","")}</h3>
            {zt_badge}
            <table><tr><th>Type</th><th>Valeur</th></tr>
            <tr><td>A</td><td>{", ".join(dns_i.get("a",[]))}</td></tr>
            <tr><td>AAAA</td><td>{", ".join(dns_i.get("aaaa",[]))}</td></tr>
            <tr><td>PTR</td><td>{dns_i.get("ptr","")}</td></tr>
            <tr><td>MX</td><td>{" | ".join(dns_i.get("mx",[])[:5])}</td></tr>
            <tr><td>NS</td><td>{" | ".join(dns_i.get("ns",[])[:5])}</td></tr>
            <tr><td>TXT</td><td style="font-size:.85em">{" | ".join(dns_i.get("txt",[])[:3])}</td></tr>
            <tr><td>Subdomains</td><td style="color:var(--acc)">{subs}</td></tr>
            </table></div>'''

        # Traceroute
        trace_html=''
        if trace:
            rows=''
            for h in trace:
                ms=f'{h["rtt_ms"]} ms' if h.get("rtt_ms") else '* ms'
                hn2=f' ({h["hostname"]})' if h.get('hostname') else ''
                bar_w=min(int((h.get('rtt_ms') or 0)/5),200)
                rows+=f'''<tr>
                  <td>{h["hop"]}</td>
                  <td>{h["ip"]}{hn2}</td>
                  <td>{ms} <div style="height:3px;width:{bar_w}px;background:var(--acc);opacity:.6;display:inline-block;margin-left:5px"></div></td>
                </tr>'''
            trace_html=f'''<div class="section">
            <h3>🛤 Traceroute</h3>
            <table><tr><th>Hop</th><th>IP</th><th>Latence</th></tr>{rows}</table>
            </div>'''

        # Vulns
        vuln_html=''
        if vulns:
            rows=''.join(f'<tr><td>{p}</td><td><span class="badge {sev}">{sev}</span></td>'
                         f'<td>{name}</td><td>{desc}</td></tr>'
                         for p,sev,name,desc in vulns)
            vuln_html=f'''<div class="section">
            <h3>⚠ Risques détectés</h3>
            <table><tr><th>Port</th><th>Sévérité</th><th>Service</th><th>Description</th></tr>
            {rows}</table></div>'''

        return f'''<div class="section">
        <h2>🖥 Hôte: {ip} {f"({hn})" if hn else ""}</h2>
        <p>OS estimé: <b>{os_g}</b> (confiance {os_c}%) | TTL: {r.get("ttl","?")}</p>
        {"<table><tr><th>Port</th><th>Proto</th><th>État</th><th>Service</th><th>Banner</th><th>Risque</th></tr>"+port_rows+"</table>" if port_rows else "<p style='color:#555'>Aucun port ouvert</p>"}
        </div>
        {ssl_html}{http_html}{dns_html}{trace_html}{vuln_html}'''

# ══════════════════════════════════════════════════════════
# CURSES TUI
# ══════════════════════════════════════════════════════════
class CursesTUI:
    def __init__(self, state: ScanState):
        self.state = state

    def run(self, scan_func):
        """Launch curses wrapper, run scan_func in background thread."""
        t = threading.Thread(target=scan_func, daemon=True)
        t.start()
        try:
            import curses
            curses.wrapper(self._draw)
        except Exception:
            # Fallback if curses unavailable
            t.join()

    def _draw(self, stdscr):
        import curses
        curses.start_color(); curses.use_default_colors()
        curses.init_pair(1,curses.COLOR_GREEN,-1)
        curses.init_pair(2,curses.COLOR_CYAN,-1)
        curses.init_pair(3,curses.COLOR_YELLOW,-1)
        curses.init_pair(4,curses.COLOR_RED,-1)
        curses.init_pair(5,curses.COLOR_WHITE,-1)
        curses.curs_set(0)
        stdscr.nodelay(True)

        G=curses.color_pair(1); CY=curses.color_pair(2)
        Y=curses.color_pair(3);  R=curses.color_pair(4)
        W=curses.color_pair(5)

        while not self.state.done:
            try:
                stdscr.erase()
                h,w = stdscr.getmaxyx()

                # Header
                title=' NetScanner Pro v3.0 — LIVE SCAN '
                stdscr.addstr(0,0,'─'*w, G)
                stdscr.addstr(1,max(0,(w-len(title))//2), title, G|curses.A_BOLD)
                stdscr.addstr(2,0,'─'*w, G)

                # Stats row
                elapsed=int(time.time()-self.state.start)
                with self.state.lock:
                    cur  = self.state.current
                    prog = self.state.progress
                    tot  = self.state.total
                    ports_found = len(self.state.results[0]['ports']) if self.state.results else 0
                pct = int(prog/tot*100) if tot else 0
                bar_w=min(w-20,40)
                filled=int(pct/100*bar_w)
                bar='█'*filled+'░'*(bar_w-filled)
                stdscr.addstr(3,2,f'Cible: ',CY)
                stdscr.addstr(3,9,cur[:w-40] if cur else '...',W)
                stdscr.addstr(3,w-30,f'[{bar}] {pct}%',G)
                stdscr.addstr(4,2,f'Ports scannés: {prog}/{tot} | Ouverts: {ports_found} | Temps: {elapsed}s',Y)
                stdscr.addstr(5,0,'─'*w, G)

                # Open ports (left panel)
                panel_h = h-12
                stdscr.addstr(6,2,'PORT      PROTO  SERVICE         BANNER',CY|curses.A_BOLD)
                stdscr.addstr(7,2,'─'*(w//2-4),CY)
                row=8
                with self.state.lock:
                    all_ports=[]
                    for r in self.state.results:
                        for p in r.get('ports',[]):
                            all_ports.append((r['ip'],p))
                for ip,p in all_ports[-(panel_h):]:
                    if row>=h-4: break
                    svc=(p.get('service','?')+'              ')[:14]
                    ban=(p.get('banner','')+'             ')[:20]
                    col = R if VULN_DB.get(p['port'],('','',''))[0]=='CRIT' else \
                          Y if VULN_DB.get(p['port'],('','',''))[0]=='HIGH' else G
                    line=f'{p["port"]:<10}{p["proto"]:<7}{svc}{ban}'
                    stdscr.addstr(row,2,line[:w//2-4], col)
                    row+=1

                # Log panel (right side)
                log_x=w//2+2
                stdscr.addstr(6,log_x,'── LOG ──',CY|curses.A_BOLD)
                log_row=7
                with self.state.lock:
                    recent_logs=self.state.log[-(panel_h+1):]
                for msg in recent_logs:
                    if log_row>=h-4: break
                    max_len=w-log_x-2
                    stdscr.addstr(log_row,log_x,msg[:max_len],curses.color_pair(0))
                    log_row+=1

                # Footer
                stdscr.addstr(h-3,0,'─'*w,G)
                stdscr.addstr(h-2,2,'[q] Quitter  [r] Rafraîchir  Scan en cours...',CY)
                stdscr.refresh()

                # Input
                key=stdscr.getch()
                if key==ord('q'): self.state.done=True; break
                time.sleep(0.2)
            except curses.error:
                pass
            except Exception:
                pass

        # Final screen
        try:
            stdscr.erase()
            stdscr.addstr(0,0,' SCAN TERMINÉ ',curses.color_pair(1)|curses.A_BOLD)
            with self.state.lock:
                total_open=sum(len(r.get('ports',[])) for r in self.state.results)
                stdscr.addstr(2,2,f'Hôtes: {len(self.state.results)} | Ports ouverts: {total_open}',
                              curses.color_pair(2))
            stdscr.addstr(4,2,'Appuyez sur une touche pour quitter...',curses.color_pair(5))
            stdscr.refresh()
            stdscr.nodelay(False)
            stdscr.getch()
        except Exception:
            pass

# ══════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════
class NetScannerPro:
    def __init__(self, args, state: ScanState):
        self.args      = args
        self.state     = state
        self.discovery = HostDiscovery(args.timeout)
        self.tcp_scan  = TCPScanner(args.timeout)
        self.syn_scan  = SYNScanner(args.timeout) if args.syn else None
        self.ssl_insp  = SSLInspector(args.timeout)
        self.http_anal = HTTPAnalyzer(args.timeout)
        self.dns_recon = DNSRecon(args.timeout)
        self.tracer    = Tracer(args.max_hops, args.timeout) if args.trace else None
        self.os_fp     = OSFingerprint(args.timeout)
        self.reporter  = HTMLReporter()

    def run(self):
        ports = build_port_list(self.args.ports)
        target= self.args.target

        # Discover hosts
        if '/' in target or self.args.discover:
            if not self.args.tui:
                print(f'  {C.CY}Découverte des hôtes sur {target}...{C.N}')
            hosts = self.discovery.scan_network(target, state=self.state)
            if not self.args.tui:
                print(f'  {C.G}[✓]{C.N} {len(hosts)} hôtes actifs\n')
        else:
            try:
                ip = socket.gethostbyname(target)
                if not self.args.tui and ip!=target:
                    print(f'  {C.DIM}Résolution: {target} → {ip}{C.N}')
            except socket.gaierror:
                print(f'{C.R}[!] Impossible de résoudre {target}{C.N}')
                self.state.done=True; return
            hosts = [{'ip':ip,'hostname':target if ip!=target else '',
                      'ttl':None,'os_guess':'Unknown'}]

        self.state.total = len(hosts)*len(ports)
        all_results=[]

        for host in hosts:
            ip = host['ip']
            self.state.current = ip
            self.state.push_log(f'Scan de {ip}')
            t0=time.time()

            # Port scan
            if self.args.syn and self.syn_scan:
                self.state.push_log(f'{ip}: SYN scan...')
                syn_res=self.syn_scan.scan(ip, ports)
                if syn_res is None:
                    self.state.push_log('SYN scan: pas root — TCP connect à la place')
                    open_ports=self.tcp_scan.scan(ip,ports,self.args.workers,self.state)
                else:
                    open_ports=syn_res
                    self.state.progress+=len(ports)
            else:
                open_ports=self.tcp_scan.scan(ip,ports,self.args.workers,self.state)

            open_nums=[p['port'] for p in open_ports]
            self.state.push_log(f'{ip}: {len(open_ports)} ports ouverts')

            # SSL
            ssl_res={}
            if not self.args.no_ssl:
                for p in [443,8443]+[p['port'] for p in open_ports if p['port'] not in (443,8443)]:
                    if p in open_nums:
                        self.state.push_log(f'{ip}: SSL inspect :{p}')
                        s=self.ssl_insp.inspect(ip,p)
                        if s.get('enabled'):
                            ssl_res=s; break

            # HTTP
            http_res={}
            if not self.args.no_http:
                for p,tls in [(443,True),(80,False),(8443,True),(8080,False)]:
                    if p in open_nums:
                        self.state.push_log(f'{ip}: HTTP analyse :{p}')
                        http_res=self.http_anal.analyze(ip,p,tls)
                        if http_res.get('status'): break

            # DNS
            dns_res={}
            if not self.args.no_dns and (53 in open_nums or host.get('hostname')):
                target_dn=host['hostname'] or ip
                self.state.push_log(f'DNS recon: {target_dn}')
                dns_res=self.dns_recon.recon(target_dn)

            # Traceroute
            trace_res=[]
            if self.tracer:
                self.state.push_log(f'Traceroute vers {ip}')
                trace_res=self.tracer.trace(ip)

            # OS fingerprint
            banners={p['port']:p['banner'] for p in open_ports}
            os_info=self.os_fp.fingerprint(host, open_ports, banners)

            # Vulns
            vulns=[]
            for p in open_nums:
                if p in VULN_DB:
                    sev,name,desc=VULN_DB[p]
                    vulns.append((p,sev,name,desc))
            vulns.sort(key=lambda x:['CRIT','HIGH','MED','INFO'].index(x[1]) if x[1] in ['CRIT','HIGH','MED','INFO'] else 9)

            result={**host,'ports':open_ports,'ssl':ssl_res,
                    'http':http_res,'dns':dns_res,'trace':trace_res,
                    'os':os_info,'vulns':vulns,'scan_time':round(time.time()-t0,2)}
            all_results.append(result)
            with self.state.lock:
                self.state.results=all_results

            if not self.args.tui:
                self._print_host(result)

        # Save reports
        if self.args.output:
            json_f=self.args.output+'.json'
            html_f=self.args.output+'.html'
            with open(json_f,'w') as f:
                json.dump(all_results,f,indent=2,default=str)
            self.reporter.generate(all_results, html_f)
            if not self.args.tui:
                print(f'\n{C.G}[✓]{C.N} JSON → {C.W}{json_f}{C.N}')
                print(f'{C.G}[✓]{C.N} HTML → {C.W}{html_f}{C.N}')

        if not self.args.tui:
            self._print_summary(all_results)
        self.state.done=True

    def _print_host(self, r):
        ip=r['ip']; hn=r.get('hostname','')
        os_g=r['os']['guess']; os_c=r['os']['confidence']
        print(f'\n{C.G}{"═"*65}{C.N}')
        print(f'{C.W}{C.BO}  {ip}{f" ({hn})" if hn else ""}{C.N}  '
              f'{C.DIM}OS: {os_g} ({os_c}%) | {r.get("scan_time","?")}s{C.N}')
        print(f'{C.G}{"─"*65}{C.N}')

        if r['ports']:
            print(f'  {C.BO}{"PORT":<10}{"PROTO":<8}{"SERVICE":<16}{"METHOD":<9}BANNER{C.N}')
            for p in r['ports']:
                v=VULN_DB.get(p['port'])
                sev_col=(C.R if v and v[0]=='CRIT' else
                         C.Y if v and v[0]=='HIGH' else
                         C.M if v and v[0]=='MED' else C.G) if v else C.G
                ban=(p['banner'][:40]+'…') if len(p['banner'])>40 else p['banner']
                print(f'  {sev_col}{p["port"]:<10}{C.N}'
                      f'{p["proto"]:<8}{C.CY}{p.get("service","?"):<16}{C.N}'
                      f'{C.DIM}{p.get("method","TCP"):<9}{ban}{C.N}')
        else:
            print(f'  {C.DIM}Aucun port ouvert{C.N}')

        if r.get('ssl',{}).get('enabled'):
            s=r['ssl']
            dl=s.get('days_left',0); col=C.G if dl>30 else C.R
            print(f'\n  {C.CY}SSL:{C.N} {s.get("version","")} | {s.get("cipher","")} ({s.get("bits","")} bits)')
            print(f'  {C.CY}Cert:{C.N} CN={s["subject"].get("commonName","?")} | '
                  f'Expiry: {col}{s.get("expiry","?")} ({dl}j){C.N}')
            if s.get('self_signed'): print(f'  {C.Y}⚠  Certificat auto-signé{C.N}')

        if r.get('http',{}).get('status'):
            h=r['http']
            missing=len(h.get('missing_sec',[]))
            col=C.G if missing<3 else C.Y if missing<6 else C.R
            print(f'\n  {C.CY}HTTP:{C.N} {h.get("status","")} | '
                  f'Server: {h.get("server","?")} | '
                  f'Tech: {", ".join(h.get("tech",[]) or ["?"])}')
            print(f'  {C.CY}Sec-Headers:{C.N} {col}{8-missing}/8 présents{C.N}')
            sens=[p for p,c in h.get('paths',{}).items() if c==200]
            if sens: print(f'  {C.R}⚠  Chemins sensibles: {", ".join(sens)}{C.N}')

        if r.get('dns',{}).get('a'):
            d=r['dns']
            print(f'\n  {C.CY}DNS:{C.N} A={", ".join(d.get("a",[]))} | '
                  f'MX={len(d.get("mx",[]))} | NS={len(d.get("ns",[]))} | '
                  f'Subs: {len(d.get("subdomains",[]))} trouvés')
            if d.get('zone_transfer'): print(f'  {C.R}🚨 ZONE TRANSFER: {d["zone_transfer"]}{C.N}')

        if r.get('trace'):
            hops=r['trace']
            print(f'\n  {C.CY}Traceroute:{C.N} {len(hops)} sauts vers {ip}')
            for h in hops[:5]:
                ms=f'{h["rtt_ms"]}ms' if h.get("rtt_ms") else '?ms'
                print(f'  {C.DIM}  {h["hop"]:2}. {h["ip"]} — {ms}{C.N}')
            if len(hops)>5: print(f'  {C.DIM}  ... (+{len(hops)-5} sauts){C.N}')

        if r.get('vulns'):
            print(f'\n  {C.R}Risques:{C.N}')
            for p,sev,name,desc in r['vulns']:
                col=C.R if sev=='CRIT' else C.Y if sev=='HIGH' else C.M
                print(f'  {col}[{sev}] Port {p}/{name}: {desc}{C.N}')

    def _print_summary(self, results):
        total_open=sum(len(r['ports']) for r in results)
        total_crit=sum(sum(1 for p in r['ports']
                        if VULN_DB.get(p['port'],('','',''))[0]=='CRIT')
                       for r in results)
        elapsed=int(time.time()-self.state.start)
        print(f'\n{C.G}{"═"*65}{C.N}')
        print(f'{C.G}{C.BO}  RÉSUMÉ{C.N}')
        print(f'  Hôtes scannés : {C.W}{len(results)}{C.N}')
        print(f'  Ports ouverts : {C.W}{total_open}{C.N}')
        print(f'  Risques CRIT  : {C.R}{total_crit}{C.N}')
        print(f'  Durée         : {C.W}{elapsed}s{C.N}')
        print(f'{C.G}{"═"*65}{C.N}\n')

# ══════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════
def parse_args():
    p=argparse.ArgumentParser(
        description='NetScanner Pro v3.0 — Scanner réseau autonome',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXEMPLES:
  python3 netscanner.py 192.168.1.1
  python3 netscanner.py 192.168.1.0/24 --discover
  python3 netscanner.py 192.168.1.1 -p top1000 --syn --trace
  python3 netscanner.py example.com -p 80,443 -o rapport
  python3 netscanner.py 192.168.1.0/24 --tui -o rapport
""")
    p.add_argument('target')
    p.add_argument('-p','--ports',   default='top100',
                   help='top100(def)|top1000|all|1-1024|22,80,443')
    p.add_argument('-T','--timeout', type=float, default=1.0)
    p.add_argument('-w','--workers', type=int,   default=300)
    p.add_argument('--syn',          action='store_true', help='SYN scan (root requis)')
    p.add_argument('--trace',        action='store_true', help='Traceroute')
    p.add_argument('--max-hops',     type=int,   default=20)
    p.add_argument('--discover',     action='store_true', help='Découverte seule')
    p.add_argument('--no-ssl',       action='store_true')
    p.add_argument('--no-http',      action='store_true')
    p.add_argument('--no-dns',       action='store_true')
    p.add_argument('-o','--output',  default='', help='Préfixe rapport (.json + .html)')
    p.add_argument('--tui',          action='store_true', help='Interface TUI curses')
    p.add_argument('--save-progress', action='store_true', help='Sauvegarde JSON partielle pendant le scan')
    p.add_argument('--save-interval', type=float, default=3.0,
                   help='Intervalle (s) entre sauvegardes partielles (avec --save-progress)')
    p.add_argument('--fast',         action='store_true', help='Mode rapide: augmente le nombre de workers et réduit les timeouts')
    return p.parse_args()

def main():
    args=parse_args()
    # Fast mode tweaks: reduce timeout and increase workers for speed
    if getattr(args,'fast',False):
        args.timeout = max(0.2, args.timeout/2)
        args.workers = min(args.workers*2, 1000)
    if not args.tui:
        print_banner()
        print(f'  {C.CY}Cible:{C.N}   {C.W}{args.target}{C.N}')
        print(f'  {C.CY}Ports:{C.N}   {C.W}{args.ports}{C.N} ({len(build_port_list(args.ports))} ports)')
        print(f'  {C.CY}Mode:{C.N}    {C.W}{"SYN" if args.syn else "TCP-Connect"}{C.N}'
              f'{" + Trace" if args.trace else ""}'
              f'{" + SSL" if not args.no_ssl else ""}'
              f'{" + HTTP" if not args.no_http else ""}'
              f'{" + DNS" if not args.no_dns else ""}')
        print(f'  {C.CY}Début:{C.N}   {C.W}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{C.N}\n')

    state=ScanState()
    scanner=NetScannerPro(args, state)

    # Partial progress saver (background thread) when requested
    def _progress_saver(state, prefix, interval):
        if not prefix:
            return
        out_file = prefix + '.partial.json'
        while not state.done:
            time.sleep(interval)
            try:
                with state.lock:
                    data = list(state.results)
                with open(out_file,'w',encoding='utf-8') as f:
                    json.dump(data,f,indent=2,default=str)
            except Exception:
                pass
        # final write
        try:
            with state.lock:
                data = list(state.results)
            with open(prefix + '.json','w',encoding='utf-8') as f:
                json.dump(data,f,indent=2,default=str)
        except Exception:
            pass

    if getattr(args,'save_progress',False) and args.output:
        saver = threading.Thread(target=_progress_saver, args=(state,args.output,args.save_interval), daemon=True)
        saver.start()

    # SIGINT handler to ensure partial save on Ctrl-C
    if getattr(args,'save_progress',False) and args.output:
        def _sigint_handler(sig, frame):
            state.push_log('SIGINT received — arrêt en cours')
            state.done = True
        signal.signal(signal.SIGINT, _sigint_handler)

    if args.tui:
        tui=CursesTUI(state)
        tui.run(scanner.run)
    else:
        try:
            scanner.run()
        except KeyboardInterrupt:
            print(f'\n{C.Y}[!] Scan interrompu{C.N}\n')
            sys.exit(0)

if __name__=='__main__':
    main()