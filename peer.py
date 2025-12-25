import socket
import threading
import json
import base64
import os
import time
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- CẤU HÌNH ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
BUFFER_SIZE = 65536  # Buffer lớn để chứa Ledger dài
GOSSIP_INTERVAL = 15 # Giây giữa các lần chủ động đồng bộ

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}

# --- DISTRIBUTED LEDGER & CLOCK ---
vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None 

# --- RSA ---
private_key = None
public_key_pem = ""

# --- SECURITY AT REST (AES-256) ---

def derive_key(passphrase: str):
    salt = b'distributed_systems_lab_salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def save_ledger():
    if aes_key is None: return
    filename = f"{MY_USERNAME}.json"
    with clock_lock:
        # Sắp xếp theo quan hệ nhân quả (Vector Clock)
        ledger.sort(key=lambda x: (sum(x['vc'].values()), x['sender']))
        data_str = json.dumps({"vector_clock": vector_clock, "ledger": ledger}, ensure_ascii=False)
    
    f_cipher = Fernet(aes_key)
    encrypted = f_cipher.encrypt(data_str.encode('utf-8'))
    with open(filename, 'wb') as f:
        f.write(encrypted)

def load_ledger(passphrase: str):
    global ledger, vector_clock, aes_key
    filename = f"{MY_USERNAME}.json"
    aes_key = derive_key(passphrase)
    if os.path.exists(filename):
        try:
            with open(filename, 'rb') as f:
                decrypted = Fernet(aes_key).decrypt(f.read()).decode('utf-8')
            data = json.loads(decrypted)
            ledger = data.get('ledger', [])
            vector_clock = data.get('vector_clock', {})
            return True
        except: return False
    return True

# --- RSA & SYNC LOGIC ---

def generate_keys():
    global private_key, public_key_pem
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def decrypt_msg(enc_b64):
    try:
        return private_key.decrypt(
            base64.b64decode(enc_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode('utf-8')
    except: return "[Encrypted for other peer]"

def sync_data(remote_ledger, remote_vc):
    global ledger, vector_clock
    with clock_lock:
        # Anti-Entropy: Merge logs (De-duplication)
        local_sigs = {json.dumps(m, sort_keys=True) for m in ledger}
        for m in remote_ledger:
            if json.dumps(m, sort_keys=True) not in local_sigs:
                ledger.append(m)
        # Vector Clock: Max update
        all_nodes = set(vector_clock.keys()) | set(remote_vc.keys())
        for n in all_nodes:
            vector_clock[n] = max(vector_clock.get(n, 0), remote_vc.get(n, 0))
        save_ledger()

# --- NETWORKING & GOSSIP ---

def anti_entropy_loop():
    """Gossip Protocol: Chủ động lan truyền dữ liệu"""
    while True:
        time.sleep(GOSSIP_INTERVAL)
        if not PEER_LIST or not MY_USERNAME or aes_key is None: continue
        
        targets = [u for u in PEER_LIST.keys() if u != MY_USERNAME]
        if not targets: continue
        
        target = random.choice(targets)
        info = PEER_LIST[target]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((info['ip'], info['p2p_port']))
            with clock_lock:
                payload = {"sender": MY_USERNAME, "type": "GOSSIP", "vector_clock": dict(vector_clock), "ledger": ledger}
            s.sendall(json.dumps(payload).encode('utf-8'))
            s.close()
        except: pass

def handle_p2p(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        payload = json.loads(data)
        sync_data(payload.get('ledger', []), payload.get('vector_clock', {}))
        
        if payload.get('type') == 'CHAT':
            decrypted = decrypt_msg(payload.get('content'))
            print(f"\n<<< {payload['sender']} >>>: {decrypted}")
            print(f"Nhập lệnh > ", end="", flush=True)
    except: pass
    finally: conn.close()

def p2p_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', MY_P2P_PORT)); s.listen(10)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle_p2p, args=(c, a), daemon=True).start()

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    pwd = input(f"Passphrase cho {MY_USERNAME}: ")
    if not load_ledger(pwd): return
    MY_P2P_PORT = int(input("P2P Port: "))

    # Discovery Register
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command": "REGISTER", "username": MY_USERNAME, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem}).encode('utf-8'))
        s.recv(1024); s.close()
    except: print("Server Offline!"); return

    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=anti_entropy_loop, daemon=True).start()

    while True:
        line = input("Nhập lệnh > ").strip()
        if not line: continue
        args = line.split(' ', 2)
        cmd = args[0].upper()

        if cmd == 'EXIT': break
        elif cmd == 'UPDATE':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps({"command": "GET_PEERS"}).encode('utf-8'))
            PEER_LIST = json.loads(s.recv(BUFFER_SIZE).decode('utf-8')).get('peers', {})
            s.close()
            print("[HỆ THỐNG] Đã cập nhật danh bạ.")
        elif cmd == 'CHAT' and len(args) == 3:
            target = args[1].lower()
            if target in PEER_LIST:
                with clock_lock:
                    vector_clock[MY_USERNAME] = vector_clock.get(MY_USERNAME, 0) + 1
                    pub_key = PEER_LIST[target]['public_key']
                    # RSA Encrypt
                    enc = base64.b64encode(serialization.load_pem_public_key(pub_key.encode()).encrypt(
                        args[2].encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )).decode()
                    ledger.append({"sender": MY_USERNAME, "content": enc, "vc": dict(vector_clock)})
                    save_ledger()
                    payload = {"sender": MY_USERNAME, "type": "CHAT", "content": enc, "vector_clock": dict(vector_clock), "ledger": ledger}
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
                    s.connect((PEER_LIST[target]['ip'], PEER_LIST[target]['p2p_port']))
                    s.sendall(json.dumps(payload).encode('utf-8')); s.close()
                except: print("Lỗi gửi tin.")
        elif cmd == 'SHOW':
            for m in ledger: print(f"[{m['sender'].upper()}] {decrypt_msg(m['content'])}")

if __name__ == "__main__":
    main()