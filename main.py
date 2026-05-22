import os
import uuid
import random
import threading
import tempfile
import json
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Attempt to import packet libraries
try:
    import pyshark
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
    PACKET_LIBS_AVAILABLE = True
except ImportError:
    PACKET_LIBS_AVAILABLE = False

app = FastAPI(title="Megadriod NetRecon Lab")
templates = Jinja2Templates(directory="templates")

# --- IN-MEMORY DATABASE FOR LAB STATE ---
DB: Dict[str, Any] = {
    "packets": [],
    "notes": [],
    "incidents": [],
    "users": {"analyst_user": "SOC_Tier_1"},
    "system_status": "Simulated Mode",
    "scenarios": {
        "normal": "Standard Enterprise Operations (HTTP, DNS, SMB)",
        "dns_tunneling": "Data Exfiltration via DNS TXT records",
        "lateral_movement": "PsExec execution and SMB share enumerations",
        "beaconing": "C2 communication pattern to malicious external IP"
    },
    # NEW: Web Interceptor State
    "interceptor": {
        "is_active": True,           # Toggle to intercept or pass-through
        "port": 8080,                # Proxy listener port
        "queue": {},                 # Pending requests waiting for user action
        "history": []                # Log of intercepted & modified traffic
    }
}

SUSPICIOUS_DOMAINS = ["malware-c2.net", "crypto-drainer.xyz", "updates-microsoft.co", "tunnel-vps.internal"]
SUSPICIOUS_USER_AGENTS = ["Mozilla/5.0 (compatible; Nmap Scripting Engine)", "PowerShell/7.4.2"]

# --- HYBRID ENGINE: PACKET GENERATOR & CLASSIFIER ---
def generate_base_packet(protocol: str, src_ip: str, dst_ip: str, sport: int, dport: int, info: str, size: int) -> Dict[str, Any]:
    packet_id = str(uuid.uuid4())[:8]
    timestamp = datetime.utcnow()
    
    is_src_internal = src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172.") or src_ip.startswith("127.")
    is_dst_internal = dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or dst_ip.startswith("172.") or dst_ip.startswith("127.")
    traffic_map = "Internal-to-Internal" if (is_src_internal and is_dst_internal) else ("Internal-to-External" if is_src_internal else "External-to-Internal")
    
    severity = "Low"
    anomaly_score = random.randint(5, 25)
    alerts = []
    
    if any(dom in info for dom in SUSPICIOUS_DOMAINS):
        severity = "High"
        anomaly_score = 90
        alerts.append("Suspicious Domain Name Resolution Detected")
    if "TXT" in info and protocol == "DNS" and len(info) > 60:
        severity = "Critical"
        anomaly_score = 95
        alerts.append("Potential DNS Tunneling Behavior Identified")
    if protocol == "SMB" and "C$" in info:
        severity = "High"
        anomaly_score = 85
        alerts.append("Workstation-to-Workstation Administrative Share Access (Potential Lateral Movement)")
    if any(ua in info for ua in SUSPICIOUS_USER_AGENTS) or "PowerShell" in info:
        severity = "High"
        anomaly_score = 80
        alerts.append("Malicious User-Agent/PowerShell traffic indicator triggered")
    if protocol == "TCP" and size < 64:
        anomaly_score += 15
        
    if anomaly_score >= 85 and severity != "Critical": severity = "High"
    if anomaly_score >= 95: severity = "Critical"

    return {
        "id": packet_id,
        "timestamp": timestamp.isoformat() + "Z",
        "time_relative": str(timestamp.strftime("%H:%M:%S")),
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "length": size,
        "info": info,
        "direction": traffic_map,
        "severity": severity,
        "anomaly_score": anomaly_score,
        "alerts": alerts,
        "metadata_encrypted": {"ja3_fingerprint": "e3b0c44298fc1c149afbf4c8996fb924" if protocol == "HTTPS" else "N/A", "tls_version": "TLSv1.3" if protocol == "HTTPS" else "N/A"}
    }

# --- REAL LIVE CAPTURE THREAD (SCAPY) ---
def process_live_packet(packet):
    """Callback for Scapy sniff(). Converts real packets to our dashboard format."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        protocol = "IP"
        sport, dport = 0, 0
        info = f"Raw IPv4 Packet - Size: {size} bytes"

        if TCP in packet:
            protocol = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
            flags = packet[TCP].flags
            info = f"TCP Session Tracking Port {sport} -> {dport} [Flags: {flags}]"
        elif UDP in packet:
            protocol = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport
            info = f"UDP Session Port {sport} -> {dport}"
            if DNS in packet:
                protocol = "DNS"
                info = "DNS Query/Response Activity"
        elif ICMP in packet:
            protocol = "ICMP"
            info = f"ICMP Activity - Type {packet[ICMP].type}"

        if sport == 443 or dport == 443: protocol = "HTTPS"
        elif sport == 80 or dport == 80: protocol = "HTTP"
        elif sport == 445 or dport == 445: protocol = "SMB"

        pkt_data = generate_base_packet(protocol, src_ip, dst_ip, sport, dport, info, size)
        
        DB["packets"].insert(0, pkt_data)
        DB["packets"] = DB["packets"][:250] 

def start_live_capture_thread():
    if not PACKET_LIBS_AVAILABLE:
        print("[ERROR] Scapy/Pyshark not installed. Please pip install them.")
        return
    try:
        print("[INFO] Initiating Real Live Scapy Packet Capture...")
        sniff(prn=process_live_packet, store=False)
        DB["system_status"] = "Live Scapy Capture ACTIVE"
    except Exception as e:
        print(f"[ERROR] Live Capture failed to attach to interface. Are you running as Admin/Root? Error: {e}")
        DB["system_status"] = "Capture Failed (Requires Admin/Root)"

capture_thread = threading.Thread(target=start_live_capture_thread, daemon=True)
capture_thread.start()


# --- INTERCEPTOR PROXY THREAD ---
class ProxyInterceptorHandler(BaseHTTPRequestHandler):
    
    def do_CONNECT(self):
        """Fixes Internet Breakage: Creates a TCP Tunnel for HTTPS traffic."""
        address = self.path.split(':', 1)
        host = address[0]
        port = int(address[1]) if len(address) > 1 else 443

        try:
            target_sock = socket.create_connection((host, port), timeout=5)
            self.send_response(200, 'Connection Established')
            self.end_headers()

            sockets = [self.connection, target_sock]
            while True:
                readable, _, errs = select.select(sockets, [], sockets, 5)
                if errs or not readable:
                    break
                for sock in readable:
                    data = sock.recv(8192)
                    if not data:
                        return
                    if sock is self.connection:
                        target_sock.sendall(data)
                    else:
                        self.connection.sendall(data)
        except Exception as e:
            print(f"[PROXY] Tunnel Error to {host}: {e}")
            self.send_error(502, "Bad Gateway")

    def handle_request_flow(self):
        """Handles HTTP Traffic Interception"""
        # Prevent intercepting the dashboard itself to avoid infinite loops
        if "127.0.0.1:8000" in self.path or "localhost:8000" in self.path:
            self.forward_request({"url": self.path, "method": self.command, "headers": dict(self.headers), "body": ""})
            return

        req_id = str(uuid.uuid4())[:8]
        url = self.path
        method = self.command
        
        headers = dict(self.headers)
        body = ""
        if 'Content-Length' in headers:
            body = self.rfile.read(int(headers['Content-Length'])).decode('utf-8', errors='ignore')

        request_data = {
            "id": req_id,
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "timestamp": datetime.utcnow().strftime("%H:%M:%S")
        }

        if not DB["interceptor"]["is_active"]:
            self.forward_request(request_data)
            return

        event = threading.Event()
        DB["interceptor"]["queue"][req_id] = {
            "request": request_data,
            "status": "pending",
            "event": event,
            "modified_request": None
        }
        
        event.wait()
        
        action_state = DB["interceptor"]["queue"][req_id]
        
        if action_state["status"] == "drop":
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Request dropped by Megadriod Interceptor.")
            
        elif action_state["status"] in ["forward", "modify"]:
            target_req = action_state["modified_request"] if action_state["modified_request"] else request_data
            self.forward_request(target_req)
            
        DB["interceptor"]["history"].insert(0, action_state)
        del DB["interceptor"]["queue"][req_id]

    def forward_request(self, req_data):
        try:
            req_body = req_data["body"].encode('utf-8') if req_data["body"] else None
            req = urllib.request.Request(req_data["url"], data=req_body, method=req_data["method"])
            for k, v in req_data["headers"].items():
                if k.lower() not in ["host", "content-length"]: 
                    req.add_header(k, v)
            
            with urllib.request.urlopen(req, timeout=5) as response:
                self.send_response(response.status)
                for k, v in response.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy Error: {str(e)}".encode())

    def do_GET(self): self.handle_request_flow()
    def do_POST(self): self.handle_request_flow()
    def do_PUT(self): self.handle_request_flow()
    def do_DELETE(self): self.handle_request_flow()
    def do_OPTIONS(self): self.handle_request_flow()

def start_proxy_server():
    port = DB["interceptor"]["port"]
    try:
        server = HTTPServer(('0.0.0.0', port), ProxyInterceptorHandler)
        server.serve_forever()
    except Exception as e:
        print(f"[ERROR] Proxy failed on port {port}: {e}")

proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
proxy_thread.start()


# --- API MODELS ---
class NoteCreate(BaseModel):
    packet_id: str
    text: str

class IncidentEscalation(BaseModel):
    incident_id: str
    severity: str
    assigned_role: str
    details: str

class InterceptorAction(BaseModel):
    action: str # "forward", "drop", "modify"
    modified_headers: Optional[Dict[str, str]] = None
    modified_body: Optional[str] = None
    modified_url: Optional[str] = None


# --- API ROUTES ---
@app.get("/", response_class=HTMLResponse)
async def load_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/packets")
async def get_packets(
    protocol: Optional[str] = None,
    ip_filter: Optional[str] = None,
    domain_filter: Optional[str] = None,
    min_severity: Optional[str] = None
):
    filtered = DB["packets"]
    if protocol and protocol != "ALL":
        filtered = [p for p in filtered if p["protocol"].upper() == protocol.upper()]
    if ip_filter:
        filtered = [p for p in filtered if ip_filter in p["src_ip"] or ip_filter in p["dst_ip"]]
    if domain_filter:
        filtered = [p for p in filtered if domain_filter.lower() in p["info"].lower()]
    if min_severity and min_severity != "ALL":
        severity_weights = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        target_weight = severity_weights.get(min_severity, 1)
        filtered = [p for p in filtered if severity_weights.get(p["severity"], 1) >= target_weight]
    return JSONResponse(content=filtered)

@app.post("/api/recon/{tool}")
async def run_osint_tool(tool: str, target: str = Form(...)):
    """Executes 100% Real OSINT and Network commands from the host OS."""
    import subprocess
    import socket
    import ssl
    import platform
    import ipaddress

    result = ""
    is_windows = platform.system().lower() == "windows"

    try:
        if tool == "ping":
            cmd = ["ping", "-n", "4", target] if is_windows else ["ping", "-c", "4", target]
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            
        elif tool == "traceroute":
            cmd = ["tracert", target] if is_windows else ["traceroute", target]
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            
        elif tool in ["dns-a", "dns-mx", "dns-txt"]:
            record_type = tool.split("-")[1].upper()
            req = urllib.request.urlopen(f"https://dns.google/resolve?name={target}&type={record_type}")
            data = json.loads(req.read())
            if "Answer" in data:
                result = "\n".join([f"[{record_type}] -> {ans['data']} (TTL: {ans['TTL']})" for ans in data["Answer"]])
            else:
                result = f"No {record_type} records found."
                
        elif tool == "whois":
            req = urllib.request.urlopen(f"https://rdap.org/ip/{target}")
            data = json.loads(req.read())
            result = f"RDAP Name: {data.get('name', 'N/A')}\nType: {data.get('type', 'N/A')}\nCountry: {data.get('country', 'N/A')}"
            
        elif tool == "reverse-dns":
            try:
                host, alias, _ = socket.gethostbyaddr(target)
                result = f"PTR Record: {host}\nAliases: {', '.join(alias) if alias else 'None'}"
            except Exception as e:
                result = f"No PTR record found for {target} ({str(e)})"
                
        elif tool == "geoip" or tool == "asn":
            req = urllib.request.Request(f"https://ipapi.co/{target}/json/", headers={'User-Agent': 'Mozilla/5.0'})
            data = json.loads(urllib.request.urlopen(req).read())
            if tool == "geoip":
                result = f"City: {data.get('city')}\nRegion: {data.get('region')}\nCountry: {data.get('country_name')}\nCoordinates: {data.get('latitude')}, {data.get('longitude')}"
            else:
                result = f"ASN: {data.get('asn')}\nOrganization: {data.get('org')}\nNetwork: {data.get('network')}"
                
        elif tool == "port-scan":
            ports = [21, 22, 23, 53, 80, 443, 445, 3389, 8080, 8443]
            open_ports = []
            for port in ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((target, port)) == 0:
                        open_ports.append(str(port))
            result = f"Open Ports found: {', '.join(open_ports) if open_ports else 'None of the standard ports are open.'}"
            
        elif tool == "subnet-calc":
            net = ipaddress.ip_network(f"{target}/24", strict=False)
            result = f"Assuming /24 Subnet for {target}:\nNetwork: {net.network_address}\nBroadcast: {net.broadcast_address}\nHosts: {net.num_addresses - 2}"
            
        elif tool == "http-headers":
            req = urllib.request.urlopen(f"http://{target}", timeout=3)
            result = f"HTTP Status: {req.getcode()}\n" + str(req.headers)
            
        elif tool == "mac-lookup":
            req = urllib.request.Request(f"https://api.macvendors.com/{target}")
            result = urllib.request.urlopen(req).read().decode('utf-8')
            
        elif tool == "threat-intel":
            if any(dom in target for dom in SUSPICIOUS_DOMAINS) or target in ["198.51.100.42", "185.220.101.5"]:
                result = f"[!] CRITICAL THREAT DETECTED\nIndicator: {target}\nMatch found in local Megadriod IOC DB."
            else:
                result = f"[✓] Target {target} appears clean against local definitions."
                
        elif tool == "ssl-cert":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    result = f"Raw Certificate Data Length: {len(cert)} bytes (Connection Successful)"
                    
    except Exception as e:
        result = f"Error executing {tool}: {str(e)}"

    return {"status": "success", "result": result}

# --- NEW: INTERCEPTOR API ROUTES ---
@app.post("/api/interceptor/toggle")
async def toggle_interceptor(active: bool = Form(...)):
    """Turns the interceptor feature on or off."""
    DB["interceptor"]["is_active"] = active
    return {"status": "success", "is_active": active}

@app.get("/api/interceptor/queue")
async def get_interceptor_queue():
    """Returns a list of all currently paused requests waiting for SOC action."""
    queue_list = []
    for req_id, item in DB["interceptor"]["queue"].items():
        queue_list.append({
            "id": req_id,
            "request": item["request"],
            "status": item["status"]
        })
    return JSONResponse(content=queue_list)

@app.post("/api/interceptor/action/{req_id}")
async def handle_interceptor_action(req_id: str, action_data: InterceptorAction):
    """Executes 'forward', 'drop', or 'modify' on a paused request."""
    if req_id not in DB["interceptor"]["queue"]:
        raise HTTPException(status_code=404, detail="Request ID not found in intercept queue. It may have timed out.")
        
    item = DB["interceptor"]["queue"][req_id]
    
    if action_data.action == "modify":
        modified_req = dict(item["request"])
        if action_data.modified_headers: modified_req["headers"] = action_data.modified_headers
        if action_data.modified_body is not None: modified_req["body"] = action_data.modified_body
        if action_data.modified_url: modified_req["url"] = action_data.modified_url
        item["modified_request"] = modified_req
    
    item["status"] = action_data.action
    item["event"].set() # Unpause the proxy thread
    
    return {"status": "success", "action_taken": action_data.action}

@app.get("/api/interceptor/history")
async def get_interceptor_history():
    """Returns log of all modified/dropped/forwarded traffic."""
    return JSONResponse(content=[{"id": h["request"]["id"], "status": h["status"], "url": h["request"]["url"]} for h in DB["interceptor"]["history"]])

# --- EXISTING ROUTES ---
@app.post("/api/traffic/upload-pcap")
async def upload_pcap_replay(file: UploadFile = File(...)):
    if not file.filename.endswith('.pcap') and not file.filename.endswith('.pcapng') and not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Invalid extension. Lab parses .pcap, .pcapng, or .json files.")
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    parsed_count = 0
    new_packets = []
    
    try:
        if PACKET_LIBS_AVAILABLE:
            cap = pyshark.FileCapture(tmp_path)
            for pkt in cap:
                if hasattr(pkt, 'ip'):
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    size = int(pkt.length)
                    protocol = str(pkt.highest_layer).upper()
                    
                    sport = int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, 'transport_layer') and pkt.transport_layer else 0
                    dport = int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, 'transport_layer') and pkt.transport_layer else 0
                    info = f"Real PCAP Data: Payload Layer {protocol}"
                    
                    new_packets.append(generate_base_packet(protocol, src_ip, dst_ip, sport, dport, info, size))
                    parsed_count += 1
                    
                    if parsed_count >= 100:
                        break
            cap.close()
            
        if parsed_count > 0:
            DB["packets"] = new_packets + DB["packets"]
        else:
            raise Exception("No standard IP packets found or PyShark engine unavailable on host OS.")
            
    except Exception as e:
        print(f"[PYSHARK ERROR] {e}. Falling back to structural parse simulation.")
        pkt1 = generate_base_packet("DNS", "192.168.1.50", "8.8.8.8", 51000, 53, f"PCAP_REPLAY_FALLBACK: Processed {file.filename}", 1024)
        DB["packets"] = [pkt1] + DB["packets"]
        parsed_count = 1
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return {"status": "success", "filename": file.filename, "packets_parsed": parsed_count}

@app.get("/api/dashboard/stats")
async def get_dashboard_metrics():
    packets = DB["packets"]
    total = len(packets)
    proto_counts: Dict[str, int] = {}
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    
    for p in packets:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        severity_counts[p["severity"]] = severity_counts.get(p["severity"], 0) + 1

    avg_anomaly = sum(p["anomaly_score"] for p in packets) / total if total > 0 else 0

    return {
        "total_packets": total,
        "protocol_distribution": proto_counts,
        "severity_distribution": severity_counts,
        "average_anomaly_score": round(avg_anomaly, 2),
        "active_alerts_count": sum(1 for p in packets if len(p["alerts"]) > 0),
        "capture_engine_status": DB["system_status"]
    }

@app.post("/api/investigation/notes")
async def save_analyst_notes(note: NoteCreate):
    new_note = {
        "id": str(uuid.uuid4())[:6],
        "packet_id": note.packet_id,
        "text": note.text,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "analyst": DB["users"]["analyst_user"]
    }
    DB["notes"].append(new_note)
    return {"status": "success", "note": new_note}

@app.get("/api/investigation/notes")
async def fetch_all_notes():
    return JSONResponse(content=DB["notes"])

@app.post("/api/investigation/escalate")
async def escalate_incident_workflow(escalation: IncidentEscalation):
    incident = {
        "incident_id": escalation.incident_id,
        "severity": escalation.severity,
        "assigned_role": escalation.assigned_role,
        "details": escalation.details,
        "status": "OPEN_UNDER_REVIEW",
        "escalated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }
    DB["incidents"].append(incident)
    return {"status": "success", "escalation": incident}

@app.get("/api/investigation/report")
async def generate_comprehensive_report():
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_reviewed_logs": len(DB["packets"]),
        "flagged_anomalies": [p for p in DB["packets"] if p["severity"] in ["High", "Critical"]],
        "analyst_notebook_entries": DB["notes"],
        "escalated_incidents": DB["incidents"],
        "interceptor_history": [{"id": h["request"]["id"], "action": h["status"]} for h in DB["interceptor"]["history"]]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main.py:app", host="0.0.0.0", port=port, reload=True)