import socket
import threading
import json
import base64
import os
import time
import random
import sys
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- CẤU HÌNH ---
SERVER_HOST = '127.0.0.1' 
SERVER_PORT = 8888
UDP_BROADCAST_PORT = 9999 
BUFFER_SIZE = 65536
GOSSIP_INTERVAL = 20

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {} 
PENDING_RETRY_PEERS = set() 

vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None 
private_key = None
public_key_pem = ""

# --- 1. MẬT MÃ & IP ---

def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except: ip = '127.0.0.1'
    finally: s.close()
    return ip

def derive_key(passphrase: str):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'p2p_salt', iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def save_ledger():
    if aes_key is None: return
    filename = f"{MY_USERNAME}.json"
    with clock_lock:
        ledger.sort(key=lambda x: (sum(x['vc'].values()), x['sender']))
        data = {"vector_clock": vector_clock, "ledger": ledger}
    try:
        enc = Fernet(aes_key).encrypt(json.dumps(data, ensure_ascii=False).encode())
        with open(filename, 'wb') as f: f.write(enc)
    except: pass

def load_ledger(pwd):
    global ledger, vector_clock, aes_key
    aes_key = derive_key(pwd)
    path = f"{MY_USERNAME}.json"
    if os.path.exists(path):
        try:
            with open(path, 'rb') as f:
                dec = Fernet(aes_key).decrypt(f.read()).decode()
            d = json.loads(dec)
            ledger, vector_clock = d.get('ledger', []), d.get('vector_clock', {})
            return True
        except: return False
    ledger, vector_clock = [], {MY_USERNAME: 0}
    save_ledger()
    return True

# --- 2. NETWORKING ---

def background_send_task(target_ip, target_port, payload, target_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((target_ip, target_port))
        s.sendall(json.dumps(payload).encode('utf-8'))
    except:
        with clock_lock: PENDING_RETRY_PEERS.add(target_name)
    finally: s.close()

def sync_from_server():
    global PEER_LIST
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command": "GET_PEERS"}).encode())
        res = json.loads(s.recv(BUFFER_SIZE).decode())
        with clock_lock:
            for user, info in res['peers'].items():
                if user != MY_USERNAME:
                    PEER_LIST[user] = info
        print(f"[HỆ THỐNG] Đã đồng bộ {len(PEER_LIST)} người dùng từ Server.")
    except: print("[LỖI] Không thể kết nối Server để lấy danh sách.")

def udp_broadcast_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: sock.bind(('', UDP_BROADCAST_PORT))
    except: return
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            msg = json.loads(data.decode())
            if msg.get("type") == "DISCOVERY_REQ" and msg.get("sender") != MY_USERNAME:
                resp = {"type": "DISCOVERY_RES", "sender": MY_USERNAME, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem, "vc": vector_clock}
                sock.sendto(json.dumps(resp).encode(), addr)
        except: pass

def send_udp_discovery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.sendto(json.dumps({"type": "DISCOVERY_REQ", "sender": MY_USERNAME}).encode(), ('255.255.255.255', UDP_BROADCAST_PORT))
        sock.settimeout(1.5)
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                res = json.loads(data.decode())
                if res.get("type") == "DISCOVERY_RES":
                    with clock_lock:
                        PEER_LIST[res["sender"]] = {"ip": addr[0], "p2p_port": res["p2p_port"], "public_key": res["public_key"], "last_known_vc": res.get("vc", {})}
            except: break
    finally: sock.close()

def handle_p2p(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode()
        if not data: return
        p = json.loads(data)
        # Logic sync_data rút gọn ở đây
        if p.get('type') == 'CHAT':
            dec = private_key.decrypt(base64.b64decode(p['content']), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)).decode()
            print(f"\n<<< {p['sender']} >>>: {dec}\nNhập lệnh > ", end="", flush=True)
    except: pass
    finally: conn.close()

def p2p_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', MY_P2P_PORT))
    s.listen(10)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_p2p, args=(conn, addr), daemon=True).start()

def find_available_port():
    for port in range(5000, 5050):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except: continue
    return random.randint(10000, 20000)

# --- 3. MAIN ---

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST, SERVER_HOST, private_key, public_key_pem
    private_key = rsa.generate_private_key(65537, 2048)
    public_key_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    
    my_ip = get_lan_ip()
    print(f"=== P2P CHAT SYSTEM (IP: {my_ip}) ===")
    MY_USERNAME = input("Username: ").strip().lower()
    
    sh = input(f"Server Host (Mặc định {SERVER_HOST}): ").strip()
    if sh: SERVER_HOST = sh
    
    pwd = input("Passphrase: ")
    if not load_ledger(pwd): 
        print("Lỗi Passphrase!"); return
        
    MY_P2P_PORT = find_available_port()
    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=udp_broadcast_listener, daemon=True).start()

    # Register
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command": "REGISTER", "username": MY_USERNAME, "ip": my_ip, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem}).encode())
        s.close()
    except: print("[!] Chế độ Offline.")

    sync_from_server()
    send_udp_discovery()

    while True:
        try:
            line = input("Nhập lệnh > ").strip()
            if not line: continue
            args = line.split(' ', 2)
            cmd = args[0].upper()
            
            if cmd == 'EXIT': break
            elif cmd == 'SYNC': sync_from_server(); send_udp_discovery()
            elif cmd == 'PEERS':
                for u in PEER_LIST: print(f"- {u} ({PEER_LIST[u]['ip']}:{PEER_LIST[u]['p2p_port']})")
            elif cmd == 'CHAT' and len(args) == 3:
                target = args[1].lower()
                if target in PEER_LIST:
                    pub = PEER_LIST[target]['public_key']
                    enc = base64.b64encode(serialization.load_pem_public_key(pub.encode()).encrypt(
                          args[2].encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))).decode()
                    payload = {"sender": MY_USERNAME, "type": "CHAT", "content": enc, "vc": vector_clock}
                    threading.Thread(target=background_send_task, args=(PEER_LIST[target]['ip'], PEER_LIST[target]['p2p_port'], payload, target), daemon=True).start()
        except KeyboardInterrupt: break

if __name__ == "__main__":
    main()