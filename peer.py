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

# --- DISTRIBUTED LEDGER & SECURITY ---
vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None 
private_key = None
public_key_pem = ""

# --- 1. MẬT MÃ HÓA & KHỞI TẠO FILE ---

def derive_key(passphrase: str):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'enterprise_lan_p2p', iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def save_ledger():
    if aes_key is None: return
    filename = f"{MY_USERNAME}.json"
    with clock_lock:
        # Sắp xếp ledger theo Vector Clock để đảm bảo tính nhất quán
        ledger.sort(key=lambda x: (sum(x['vc'].values()), x['sender']))
        data_to_save = {
            "vector_clock": vector_clock,
            "ledger": ledger
        }
    
    try:
        f_cipher = Fernet(aes_key)
        encrypted = f_cipher.encrypt(json.dumps(data_to_save, ensure_ascii=False).encode())
        with open(filename, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        print(f"[LỖI] Không thể lưu file chat: {e}")

def load_ledger(pwd):
    global ledger, vector_clock, aes_key
    aes_key = derive_key(pwd)
    path = f"{MY_USERNAME}.json"
    
    if os.path.exists(path):
        try:
            with open(path, 'rb') as f:
                dec = Fernet(aes_key).decrypt(f.read()).decode()
            d = json.loads(dec)
            ledger = d.get('ledger', [])
            vector_clock = d.get('vector_clock', {})
            print(f"[HỆ THỐNG] Đã nạp {len(ledger)} tin nhắn cũ.")
            return True
        except Exception:
            print("[LỖI] Sai Passphrase hoặc file dữ liệu bị hỏng.")
            return False
    else:
        # Nếu chưa có file, khởi tạo mới và GHI FILE NGAY LẬP TỨC
        ledger = []
        vector_clock = {MY_USERNAME: 0}
        save_ledger() 
        print(f"[HỆ THỐNG] Đã tạo file lưu trữ chat mới: {MY_USERNAME}.json")
        return True

def save_contacts():
    try:
        data = {"last_updated": datetime.now().isoformat(), "peers": PEER_LIST}
        with open(f"{MY_USERNAME}_contacts.json", "w", encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    except: pass

def load_contacts():
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

# --- 2. GIAO TIẾP MẠNG KHÔNG TREO (NON-BLOCKING) ---

def background_send_task(target_ip, target_port, payload, target_name):
    """Thực hiện kết nối và gửi dữ liệu ở luồng phụ"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0) # Không đợi quá 3 giây
    try:
        s.connect((target_ip, target_port))
        s.sendall(json.dumps(payload).encode('utf-8'))
    except:
        with clock_lock:
            PENDING_RETRY_PEERS.add(target_name)
    finally:
        s.close()

def generate_keys():
    global private_key, public_key_pem
    private_key = rsa.generate_private_key(65537, 2048)
    public_key_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def decrypt_msg(enc):
    try: return private_key.decrypt(base64.b64decode(enc), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)).decode()
    except: return "[Nội dung mã hóa]"

def get_delta_ledger(remote_vc):
    delta = []
    with clock_lock:
        for msg in ledger:
            is_new = any(count > remote_vc.get(node, 0) for node, count in msg['vc'].items())
            if is_new: delta.append(msg)
    return delta

def sync_data(r_ledger, r_vc, sender_name):
    global ledger, vector_clock
    new_found = False
    with clock_lock:
        l_sigs = {json.dumps(m, sort_keys=True) for m in ledger}
        for m in r_ledger:
            if json.dumps(m, sort_keys=True) not in l_sigs:
                ledger.append(m)
                new_found = True
        for n in (set(vector_clock.keys()) | set(r_vc.keys())):
            vector_clock[n] = max(vector_clock.get(n, 0), r_vc.get(n, 0))
        if sender_name in PEER_LIST:
            PEER_LIST[sender_name]['last_known_vc'] = r_vc
    
    if new_found:
        save_ledger()

def retry_and_gossip_thread():
    while True:
        time.sleep(GOSSIP_INTERVAL)
        if not PEER_LIST or not MY_USERNAME or aes_key is None: continue
        
        with clock_lock:
            targets = list(PENDING_RETRY_PEERS) if PENDING_RETRY_PEERS else [random.choice(list(PEER_LIST.keys()))]
        
        for target in targets:
            if target == MY_USERNAME or target not in PEER_LIST: continue
            info = PEER_LIST[target]
            payload = {
                "sender": MY_USERNAME, 
                "type": "GOSSIP", 
                "vector_clock": dict(vector_clock), 
                "ledger": get_delta_ledger(info.get('last_known_vc', {}))
            }
            threading.Thread(target=background_send_task, args=(info['ip'], info['p2p_port'], payload, target), daemon=True).start()

# --- 3. LISTENERS ---

def udp_broadcast_listener():
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
                resp = {"type": "DISCOVERY_RES", "sender": MY_USERNAME, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem, "vc": vector_clock}
                sock.sendto(json.dumps(resp).encode(), addr)
        except: pass

def send_udp_discovery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2.0)
    try:
        sock.sendto(json.dumps({"type": "DISCOVERY_REQ", "sender": MY_USERNAME}).encode(), ('255.255.255.255', UDP_BROADCAST_PORT))
        start = time.time()
        while time.time() - start < 2:
            try:
                data, addr = sock.recvfrom(2048)
                res = json.loads(data.decode())
                if res.get("type") == "DISCOVERY_RES":
                    with clock_lock:
                        PEER_LIST[res["sender"]] = {"ip": addr[0], "p2p_port": res["p2p_port"], "public_key": res["public_key"], "last_known_vc": res.get("vc", {})}
            except: break
    finally:
        sock.close()

def handle_p2p(conn, addr):
    try:
        conn.settimeout(5.0)
        data = conn.recv(BUFFER_SIZE).decode()
        if not data: return
        p = json.loads(data)
        sync_data(p.get('ledger', []), p.get('vector_clock', {}), p.get('sender'))
        if p.get('type') == 'CHAT':
            print(f"\n<<< {p['sender']} >>>: {decrypt_msg(p['content'])}\nNhập lệnh > ", end="", flush=True)
    except: pass
    finally: conn.close()

def p2p_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', MY_P2P_PORT))
        s.listen(10)
        while True:
            try:
                s.settimeout(1.0)
                conn, addr = s.accept()
                threading.Thread(target=handle_p2p, args=(conn, addr), daemon=True).start()
            except socket.timeout: continue
    except: pass

# --- 4. MAIN ---

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    
    try:
        print("=== P2P CHAT SYSTEM (LAN) ===")
        MY_USERNAME = input("Username: ").strip().lower()
        if not MY_USERNAME: return
        pwd = input(f"Passphrase cho {MY_USERNAME}: ")
        if not load_ledger(pwd): return
        MY_P2P_PORT = int(input("P2P Port: "))

        threading.Thread(target=p2p_listener, daemon=True).start()
        threading.Thread(target=udp_broadcast_listener, daemon=True).start()

        # Connect Server
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps({"command": "REGISTER", "username": MY_USERNAME, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem}).encode())
            s.close()
            print("[HỆ THỐNG] Đã kết nối Server.")
        except: print("[HỆ THỐNG] Chế độ LAN Offline.")

        send_udp_discovery()
        load_contacts()
        threading.Thread(target=retry_and_gossip_thread, daemon=True).start()

        while True:
            try:
                line = input("Nhập lệnh > ").strip()
                if not line: continue
                args = line.split(' ', 2)
                cmd = args[0].upper()
                
                if cmd == 'EXIT': break
                elif cmd == 'UPDATE': 
                    send_udp_discovery(); save_contacts()
                    print(f"[HỆ THỐNG] Đã cập nhật danh bạ ({len(PEER_LIST)} Peer).")
                elif cmd == 'PEERS':
                    for u in PEER_LIST: print(f"- {u} ({PEER_LIST[u]['ip']})")
                elif cmd == 'CHAT' and len(args) == 3:
                    target = args[1].lower()
                    if target == MY_USERNAME:
                        print("[LỖI] Không thể tự chat."); continue
                    if target in PEER_LIST:
                        with clock_lock:
                            vector_clock[MY_USERNAME] += 1
                            pub = PEER_LIST[target]['public_key']
                            enc = base64.b64encode(serialization.load_pem_public_key(pub.encode()).encrypt(
                                args[2].encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))).decode()
                            ledger.append({"sender": MY_USERNAME, "content": enc, "vc": dict(vector_clock)})
                        
                        save_ledger() # Lưu file ngay sau khi cập nhật ledger RAM
                        
                        payload = {
                            "sender": MY_USERNAME, "type": "CHAT", "content": enc, 
                            "vector_clock": dict(vector_clock), 
                            "ledger": get_delta_ledger(PEER_LIST[target].get('last_known_vc', {}))
                        }
                        threading.Thread(target=background_send_task, args=(PEER_LIST[target]['ip'], PEER_LIST[target]['p2p_port'], payload, target), daemon=True).start()
                        print(f"[OK] Đang gửi tin tới {target}...")
                    else:
                        print(f"[LỖI] Không tìm thấy '{target}'. Hãy gõ UPDATE.")
                elif cmd == 'HISTORY':
                    for m in ledger:
                        dec = decrypt_msg(m['content'])
                        if m['sender'] == MY_USERNAME or dec != "[Nội dung mã hóa]":
                            print(f"[{m['sender'].upper()}] {dec}")
            except EOFError: break
    except KeyboardInterrupt:
        print("\n[HỆ THỐNG] Đang thoát...")
    finally:
        save_ledger()
        save_contacts()
        sys.exit(0)

if __name__ == "__main__":
    main()