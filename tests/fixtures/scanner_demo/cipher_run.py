"""Verify accepted deprecated CBC/static-RSA suites with real local TLS probes."""
import sys,ssl,subprocess,tempfile,threading,json,os
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
import verification as v, webraptor as w
from types import SimpleNamespace
os.environ['PATH']=str(ROOT/'.venv/bin')+':'+os.environ['PATH']
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers()
 def log_message(self,*a): pass
with tempfile.TemporaryDirectory() as t:
 cert,key=Path(t)/'cert.pem',Path(t)/'key.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);ctx.maximum_version=ssl.TLSVersion.TLSv1_2;ctx.set_ciphers('AES128-SHA:@SECLEVEL=0')
 server=ThreadingHTTPServer(('127.0.0.1',0),H);server.socket=ctx.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=server.serve_forever,daemon=True).start()
 target=f'https://127.0.0.1:{server.server_port}/'
 folder=ROOT/'results/cipher-verification-demo'/__import__('datetime').datetime.now().strftime('%Y%m%dT%H%M%S%f');folder.mkdir(parents=True)
 a=w.parse_args([target,'--modules','sslscan,testssl','--insecure','--tool-timeout','240'])
 modules=[w.execute_module(module,target,folder,a,threading.BoundedSemaphore(1),threading.Event(),w.Redactor()) for module in a.modules]
 report=v.assess_target(target,a,folder,threading.Event(),w.run_command,w.Redactor(),modules)
 checks=json.loads((folder/'verification.json').read_text())['checks']
 finding=next(c for c in checks if c['check']=='Weak SSL/TLS Ciphers')
 print(json.dumps(finding,indent=2),flush=True)
 assert finding['verified'] and finding['status']=='found'
 assert {'sslscan','testssl'} <= {e['source'] for e in finding['evidence']}
 assert 'Weak SSL/TLS Ciphers' in (folder/'report.html').read_text()
 from output_layout import organize_output
 organize_output(folder, dict(target=target, status=report['status'], modules=modules, verification=report))
 print('Report:', folder/'report.html', flush=True)
 server.shutdown()
