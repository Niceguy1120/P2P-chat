import socket
import threading
import json
import base64
import os
import time
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
BUFFER_SIZE = 65536

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {} 
vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None 
private_key = None
public_key_pem = ""

# --- 1. TIỆN ÍCH ---

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
    save_ledger(); return True

def decrypt_msg(enc_content):
    try:
        dec = private_key.decrypt(
            base64.b64decode(enc_content),
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
        )
        return dec.decode('utf-8')
    except: return "[Nội dung mã hóa cho người khác]"

# --- 2. NETWORKING ---

def update_from_server():
    global PEER_LIST
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command": "GET_PEERS"}).encode())
        res = json.loads(s.recv(BUFFER_SIZE).decode())
        with clock_lock:
            for user, info in res['peers'].items():
                if user != MY_USERNAME: PEER_LIST[user] = info
        print(f"\n[HỆ THỐNG] Đã cập nhật {len(PEER_LIST)} người dùng từ Server.")
    except: print("\n[LỖI] Không thể kết nối tới Server.")

def send_tcp_msg(ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, port))
        s.sendall(json.dumps(payload).encode())
        s.close()
    except: pass

def handle_p2p(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode()
        if not data: return
        p = json.loads(data)
        if p.get('type') == 'CHAT':
            with clock_lock:
                ledger.append(p)
                for k, v in p['vc'].items():
                    vector_clock[k] = max(vector_clock.get(k, 0), v)
            save_ledger()
            print(f"\n<<< {p['sender'].upper()} >>>: {decrypt_msg(p['content'])}")
            print("Nhập lệnh > ", end="", flush=True)
    except: pass
    finally: conn.close()

def p2p_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', MY_P2P_PORT))
    s.listen(10)
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_p2p, args=(conn, addr), daemon=True).start()
        except: continue

# --- 3. MAIN ---

def show_help():
    print("\n" + "═"*45)
    print("      HƯỚNG DẪN LỆNH P2P CHAT")
    print("═"*45)
    print(f" {'HELP':<15} : Hiển thị bảng này")
    print(f" {'UPDATE':<15} : Đồng bộ danh sách từ Server")
    print(f" {'PEERS':<15} : Xem danh sách người online")
    print(f" {'CHAT <u/n> <msg>':<15} : Gửi tin nhắn bảo mật")
    print(f" {'HISTORY':<15} : Xem lại lịch sử chat")
    print(f" {'CLEAR':<15} : Xóa màn hình console")
    print(f" {'EXIT':<15} : Thoát ứng dụng")
    print("═"*45 + "\n")

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST, SERVER_HOST, private_key, public_key_pem
    
    private_key = rsa.generate_private_key(65537, 2048)
    public_key_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    
    my_ip = get_lan_ip()
    print(f"=== P2P CHAT SYSTEM | IP: {my_ip} ===")
    
    MY_USERNAME = input("1. Username: ").strip().lower()
    if not MY_USERNAME: return
    
    sh = input(f"2. Server IP (Mặc định {SERVER_HOST}): ").strip()
    if sh: SERVER_HOST = sh
    
    pwd = input("3. Passphrase file: ")
    if not load_ledger(pwd): 
        print("[-] Sai mật khẩu file!"); return
        
    for p in range(5000, 5050):
        try:
            test_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_s.bind(('0.0.0.0', p))
            MY_P2P_PORT = p
            test_s.close()
            break
        except: continue

    threading.Thread(target=p2p_listener, daemon=True).start()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({
            "command": "REGISTER", "username": MY_USERNAME, 
            "ip": my_ip, "p2p_port": MY_P2P_PORT, "public_key": public_key_pem
        }).encode())
        s.close()
    except: pass

    update_from_server()
    show_help()

    while True:
        try:
            line = input("Nhập lệnh > ").strip()
            if not line: continue
            
            args = line.split()
            cmd = args[0].upper()
            
            if cmd == 'HELP':
                show_help()
            
            elif cmd == 'UPDATE':
                update_from_server()
                
            elif cmd == 'PEERS':
                print(f"\n--- DANH SÁCH ONLINE ({len(PEER_LIST)}) ---")
                for u, info in PEER_LIST.items():
                    print(f"- {u:<10} | {info['ip']}:{info['p2p_port']}")
                    
            elif cmd == 'HISTORY':
                print("\n--- LỊCH SỬ TIN NHẮN ---")
                for m in ledger:
                    print(f"[{m['sender'].upper()}]: {decrypt_msg(m['content'])}")

            elif cmd == 'CLEAR':
                os.system('cls' if os.name == 'nt' else 'clear')
                show_help()
                    
            elif cmd == 'CHAT':
                if len(args) < 3:
                    print("[LỖI] Cú pháp: CHAT <tên> <nội dung>")
                    continue
                target = args[1].lower()
                msg_text = " ".join(args[2:])
                if target in PEER_LIST:
                    with clock_lock:
                        vector_clock[MY_USERNAME] = vector_clock.get(MY_USERNAME, 0) + 1
                        pub_key = serialization.load_pem_public_key(PEER_LIST[target]['public_key'].encode())
                        enc = base64.b64encode(pub_key.encrypt(
                            msg_text.encode(),
                            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
                        )).decode()
                        payload = {"sender": MY_USERNAME, "type": "CHAT", "content": enc, "vc": dict(vector_clock)}
                        ledger.append(payload)
                    save_ledger()
                    threading.Thread(target=send_tcp_msg, args=(PEER_LIST[target]['ip'], PEER_LIST[target]['p2p_port'], payload)).start()
                    print(f"[OK] Đã gửi tới {target}.")
                else:
                    print(f"[LỖI] Không thấy user '{target}'.")
            
            elif cmd == 'EXIT':
                save_ledger(); break
                
        except KeyboardInterrupt: break
        except Exception as e: print(f"Lỗi: {e}")

if __name__ == "__main__":
    main()