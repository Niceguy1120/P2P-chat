import socket
import threading
import json
import base64
import os
import time
import random
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- CẤU HÌNH HỆ THỐNG ---
SERVER_HOST = '127.0.0.1' 
SERVER_PORT = 8888
UDP_BROADCAST_PORT = 9999 
BUFFER_SIZE = 65536
GOSSIP_INTERVAL = 20  # Tăng lên 20s để tối ưu cho nhóm 20 người
RETRY_INTERVAL = 15

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {} # {username: {ip, p2p_port, public_key, last_known_vc}}
PENDING_RETRY_PEERS = set() 

# --- DISTRIBUTED LEDGER & SECURITY ---
vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None 
private_key = None
public_key_pem = ""

# --- 1. MẬT MÃ HÓA (AES-256 & RSA) ---

def derive_key(passphrase: str):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'enterprise_lan_p2p', iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def save_ledger():
    if aes_key is None: return
    with clock_lock:
        ledger.sort(key=lambda x: (sum(x['vc'].values()), x['sender']))
        data = json.dumps({"vector_clock": vector_clock, "ledger": ledger}, ensure_ascii=False)
    encrypted = Fernet(aes_key).encrypt(data.encode())
    with open(f"{MY_USERNAME}.json", 'wb') as f: f.write(encrypted)

def load_ledger(pwd):
    global ledger, vector_clock, aes_key
    aes_key = derive_key(pwd)
    path = f"{MY_USERNAME}.json"
    if os.path.exists(path):
        try:
            with open(path, 'rb') as f:
                dec = Fernet(aes_key).decrypt(f.read()).decode()
            d = json.loads(dec); ledger = d['ledger']; vector_clock = d['vector_clock']
            return True
        except: return False
    return True

def generate_keys():
    global private_key, public_key_pem
    private_key = rsa.generate_private_key(65537, 2048)
    public_key_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def decrypt_msg(enc):
    try: return private_key.decrypt(base64.b64decode(enc), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)).decode()
    except: return "[Nội dung mã hóa]"

# --- 2. TỐI ƯU HÓA ĐỒNG BỘ (DELTA SYNC & GOSSIP) ---

def get_delta_ledger(remote_vc):
    """Chỉ lấy tin nhắn mà đối phương chưa có để tránh nghẽn mạng"""
    delta = []
    with clock_lock:
        for msg in ledger:
            msg_vc = msg['vc']
            is_new = False
            for node, count in msg_vc.items():
                if count > remote_vc.get(node, 0):
                    is_new = True
                    break
            if is_new: delta.append(msg)
    return delta

def sync_data(r_ledger, r_vc, sender_name):
    global ledger, vector_clock
    with clock_lock:
        l_sigs = {json.dumps(m, sort_keys=True) for m in ledger}
        new_found = False
        for m in r_ledger:
            if json.dumps(m, sort_keys=True) not in l_sigs:
                ledger.append(m)
                new_found = True
        for n in (set(vector_clock.keys()) | set(r_vc.keys())):
            vector_clock[n] = max(vector_clock.get(n, 0), r_vc.get(n, 0))
        if sender_name in PEER_LIST:
            PEER_LIST[sender_name]['last_known_vc'] = r_vc
        if new_found: save_ledger()

def retry_and_gossip_thread():
    """Tự động gửi lại tin nhắn khi phát hiện Peer online"""
    while True:
        time.sleep(GOSSIP_INTERVAL)
        if not PEER_LIST or not MY_USERNAME or aes_key is None: continue
        
        # Ưu tiên những Peer đang nợ tin (Retry)
        targets = list(PENDING_RETRY_PEERS) if PENDING_RETRY_PEERS else [random.choice(list(PEER_LIST.keys()))]
        
        for target in targets:
            if target == MY_USERNAME or target not in PEER_LIST: continue
            info = PEER_LIST[target]
            try:
                delta = get_delta_ledger(info.get('last_known_vc', {}))
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
                s.connect((info['ip'], info['p2p_port']))
                payload = {"sender": MY_USERNAME, "type": "GOSSIP", "vector_clock": dict(vector_clock), "ledger": delta}
                s.sendall(json.dumps(payload).encode()); s.close()
                if target in PENDING_RETRY_PEERS:
                    PENDING_RETRY_PEERS.remove(target)
                    print(f"[AUTO-RETRY] Đã đồng bộ thành công với {target}.")
            except: pass

# --- 3. PHÁT HIỆN MẠNG NỘI BỘ (UDP BROADCAST) ---

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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); sock.settimeout(2)
    sock.sendto(json.dumps({"type": "DISCOVERY_REQ", "sender": MY_USERNAME}).encode(), ('255.255.255.255', UDP_BROADCAST_PORT))
    start = time.time()
    while time.time() - start < 2:
        try:
            data, addr = sock.recvfrom(2048); res = json.loads(data.decode())
            if res.get("type") == "DISCOVERY_RES":
                PEER_LIST[res["sender"]] = {"ip": addr[0], "p2p_port": res["p2p_port"], "public_key": res["public_key"], "last_known_vc": res.get("vc", {})}
        except: break
    sock.close()

# --- 4. GIAO TIẾP P2P ---

def handle_p2p(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode()
        if not data: return
        p = json.loads(data)
        sync_data(p.get('ledger', []), p.get('vector_clock', {}), p.get('sender'))
        if p.get('type') == 'CHAT':
            print(f"\n<<< {p['sender']} >>>: {decrypt_msg(p['content'])}\nNhập lệnh > ", end="", flush=True)
    except: pass
    finally: conn.close()

def p2p_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', MY_P2P_PORT)); s.listen(10)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle_p2p, args=(c, a), daemon=True).start()

# --- 5. CHƯƠNG TRÌNH CHÍNH ---

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    pwd = input(f"Passphrase cho {MY_USERNAME}: ")
    if not load_ledger(pwd): return
    MY_P2P_PORT = int(input("P2P Port: "))

    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=udp_broadcast_listener, daemon=True).start()

    # Discovery Server Check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command": "REGISTER", "username": MY_USERNAME, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem}).encode())
        s.recv(1024); s.close()
        print("[HỆ THỐNG] Đã đăng ký Discovery Server.")
    except: print("[CẢNH BÁO] Chạy chế độ LAN Discovery.")

    send_udp_discovery()
    threading.Thread(target=retry_and_gossip_thread, daemon=True).start()

    while True:
        line = input("Nhập lệnh > ").strip()
        if not line: continue
        args = line.split(' ', 2)
        cmd = args[0].upper()
        
        if cmd == 'EXIT': break
        elif cmd == 'UPDATE': 
            send_udp_discovery()
            print(f"[HỆ THỐNG] Đã làm mới danh bạ LAN ({len(PEER_LIST)} Peer).")
        elif cmd == 'PEERS':
            for u in PEER_LIST: print(f"- {u} ({PEER_LIST[u]['ip']})")
        elif cmd == 'CHAT' and len(args) == 3:
            target = args[1].lower()
            if target in PEER_LIST:
                with clock_lock:
                    vector_clock[MY_USERNAME] = vector_clock.get(MY_USERNAME, 0) + 1
                    pub = PEER_LIST[target]['public_key']
                    enc = base64.b64encode(serialization.load_pem_public_key(pub.encode()).encrypt(args[2].encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))).decode()
                    ledger.append({"sender": MY_USERNAME, "content": enc, "vc": dict(vector_clock)})
                    save_ledger()
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
                    s.connect((PEER_LIST[target]['ip'], PEER_LIST[target]['p2p_port']))
                    # Gửi tin nhắn kèm Ledger Delta
                    delta = get_delta_ledger(PEER_LIST[target].get('last_known_vc', {}))
                    s.sendall(json.dumps({"sender": MY_USERNAME, "type": "CHAT", "content": enc, "vector_clock": dict(vector_clock), "ledger": delta}).encode())
                    s.close()
                    print(f"[OK] Đã gửi tới {target}.")
                except:
                    PENDING_RETRY_PEERS.add(target)
                    print(f"[OFFLINE] {target} ngoại tuyến. Tin nhắn đã lưu và sẽ tự động gửi lại.")
        elif cmd == 'HISTORY':
            for m in ledger:
                dec = decrypt_msg(m['content'])
                if m['sender'] == MY_USERNAME or dec != "[Nội dung mã hóa]":
                    print(f"[{m['sender'].upper()}] {dec}")

if __name__ == "__main__":
    main()