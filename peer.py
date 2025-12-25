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

# --- CẤU HÌNH ---
SERVER_HOST = '127.0.0.1' 
SERVER_PORT = 8888
UDP_BROADCAST_PORT = 9999 
BUFFER_SIZE = 65536
GOSSIP_INTERVAL = 15 

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {} # {username: {ip, p2p_port, public_key}}

# --- SECURITY & LEDGER ---
vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None 
private_key = None
public_key_pem = ""

# --- 1. QUẢN LÝ DANH BẠ LOCAL (CACHE & PERSISTENCE) ---

def save_contacts():
    """Lưu danh bạ local kèm dấu thời gian"""
    data = {
        "last_updated": datetime.now().isoformat(),
        "peers": PEER_LIST
    }
    with open(f"{MY_USERNAME}_contacts.json", "w", encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def load_contacts():
    """Tải danh bạ từ file local để sẵn sàng chat ngay cả khi server chết"""
    global PEER_LIST
    path = f"{MY_USERNAME}_contacts.json"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding='utf-8') as f:
                data = json.load(f)
                PEER_LIST = data.get("peers", {})
                return datetime.fromisoformat(data.get("last_updated"))
        except: return None
    return None

# --- 2. CƠ CHẾ UDP BROADCAST (PHÒNG VỆ KHI SERVER CHẾT) ---

def udp_broadcast_listener():
    """Luôn lắng nghe yêu cầu tìm kiếm trong mạng nội bộ"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('', UDP_BROADCAST_PORT))
    except: return

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            msg = json.loads(data.decode())
            if msg.get("type") == "DISCOVERY_REQ" and msg.get("sender") != MY_USERNAME:
                # Phản hồi lại thông tin P2P của mình để Peer khác cập nhật
                resp = {
                    "type": "DISCOVERY_RES",
                    "sender": MY_USERNAME,
                    "p2p_port": MY_P2P_PORT,
                    "public_key": public_key_pem
                }
                sock.sendto(json.dumps(resp).encode(), addr)
        except: pass

def send_udp_discovery():
    """Phát tin tìm kiếm Peer xung quanh (Sử dụng khi Server không phản hồi)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2)
    
    req = {"type": "DISCOVERY_REQ", "sender": MY_USERNAME}
    # Gửi tới địa chỉ broadcast của mạng LAN
    sock.sendto(json.dumps(req).encode(), ('255.255.255.255', UDP_BROADCAST_PORT))
    
    start_time = time.time()
    while time.time() - start_time < 2:
        try:
            data, addr = sock.recvfrom(2048)
            res = json.loads(data.decode())
            if res.get("type") == "DISCOVERY_RES":
                user = res["sender"]
                with clock_lock:
                    PEER_LIST[user] = {
                        "ip": addr[0],
                        "p2p_port": res["p2p_port"],
                        "public_key": res["public_key"]
                    }
                print(f"[UDP] Đã phát hiện Peer '{user}' tại {addr[0]}")
        except: break
    sock.close()

# --- 3. BẢO MẬT & ĐỒNG BỘ (RSA, AES, GOSSIP) ---

def derive_key(passphrase: str):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'lan_p2p_salt', iterations=100000, backend=default_backend())
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
    if os.path.exists(f"{MY_USERNAME}.json"):
        try:
            with open(f"{MY_USERNAME}.json", 'rb') as f:
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

def sync_data(r_ledger, r_vc):
    global ledger, vector_clock
    with clock_lock:
        l_sigs = {json.dumps(m, sort_keys=True) for m in ledger}
        for m in r_ledger:
            if json.dumps(m, sort_keys=True) not in l_sigs: ledger.append(m)
        for n in (set(vector_clock.keys()) | set(r_vc.keys())):
            vector_clock[n] = max(vector_clock.get(n, 0), r_vc.get(n, 0))
        save_ledger()

def anti_entropy_loop():
    while True:
        time.sleep(GOSSIP_INTERVAL)
        if not PEER_LIST or not MY_USERNAME or aes_key is None: continue
        target = random.choice([u for u in PEER_LIST.keys() if u != MY_USERNAME] or [None])
        if not target: continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
            s.connect((PEER_LIST[target]['ip'], PEER_LIST[target]['p2p_port']))
            s.sendall(json.dumps({"sender":MY_USERNAME, "type":"GOSSIP", "vector_clock":dict(vector_clock), "ledger":ledger}).encode())
            s.close()
        except: pass

def handle_p2p(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode()
        if not data: return
        p = json.loads(data); sync_data(p.get('ledger', []), p.get('vector_clock', {}))
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

# --- 4. MAIN LOGIC (CHẾ ĐỘ BẢO HIỂM MẠNG LAN) ---

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    pwd = input(f"Passphrase cho {MY_USERNAME}: ")
    if not load_ledger(pwd): return
    MY_P2P_PORT = int(input("P2P Port: "))

    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=udp_broadcast_listener, daemon=True).start()

    # Bước 1: Thử Server
    server_available = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command": "REGISTER", "username": MY_USERNAME, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem}).encode())
        s.recv(1024); s.close()
        server_available = True
        print("[HỆ THỐNG] Kết nối Discovery Server thành công.")
    except:
        print("[CẢNH BÁO] Server không phản hồi. Đang sử dụng phương thức dự phòng LAN.")

    # Bước 2: Cập nhật danh bạ (Local Cache vs Server)
    last_upd = load_contacts()
    if server_available:
        # Chỉ cập nhật từ server nếu chưa có cache hoặc cache > 1 tiếng
        if last_upd is None or datetime.now() - last_upd > timedelta(hours=1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((SERVER_HOST, SERVER_PORT))
                s.sendall(json.dumps({"command": "GET_PEERS"}).encode())
                PEER_LIST = json.loads(s.recv(BUFFER_SIZE).decode()).get('peers', {})
                s.close()
                save_contacts()
                print("[HỆ THỐNG] Đã cập nhật danh bạ từ Server (Cache 1h).")
            except: pass
    else:
        # Server chết: Dùng cache local và phát UDP tìm Peer đang sống trong mạng
        if PEER_LIST: print(f"[HỆ THỐNG] Sử dụng danh bạ lưu trữ local ({len(PEER_LIST)} Peer).")
        send_udp_discovery()

    threading.Thread(target=anti_entropy_loop, daemon=True).start()

    while True:
        line = input("Nhập lệnh > ").strip()
        if not line: continue
        args = line.split(' ', 2)
        cmd = args[0].upper()
        
        if cmd == 'EXIT': break
        elif cmd == 'UPDATE': 
            # Ưu tiên cập nhật qua mạng LAN ngay lập tức
            send_udp_discovery()
            save_contacts()
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
                    s.sendall(json.dumps({"sender": MY_USERNAME, "type": "CHAT", "content": enc, "vector_clock": dict(vector_clock), "ledger": ledger}).encode())
                    s.close()
                except: print("Peer Offline. Thử lại sau.")
        elif cmd == 'HISTORY':
            for m in ledger:
                dec = decrypt_msg(m['content'])
                if m['sender'] == MY_USERNAME or dec != "[Nội dung mã hóa]":
                    print(f"[{m['sender'].upper()}] {dec}")

if __name__ == "__main__":
    main()