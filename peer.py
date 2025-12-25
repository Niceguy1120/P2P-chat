import socket
import threading
import json
import base64
import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- CẤU HÌNH HỆ THỐNG ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
BUFFER_SIZE = 32768  # Tăng buffer để truyền Ledger lớn

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}

# --- BIẾN DISTRIBUTED LEDGER & CLOCK ---
vector_clock = {}
ledger = [] 
clock_lock = threading.Lock()
aes_key = None  # Key dùng để mã hóa file cục bộ

# --- BIẾN MẬT MÃ RSA ---
private_key = None
public_key_pem = ""

# --- HÀM BẢO MẬT AES (SECURITY AT REST) ---

def derive_key(passphrase: str):
    """Sử dụng PBKDF2 để tạo Key từ Passphrase"""
    salt = b'p2p_fixed_salt_for_lab' # Trong thực tế nên dùng salt ngẫu nhiên
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def save_ledger():
    """Mã hóa toàn bộ sổ cái và lưu xuống file"""
    global aes_key
    if aes_key is None: return
    
    filename = f"{MY_USERNAME}.json"
    # Sắp xếp trước khi lưu
    ledger.sort(key=lambda x: (sum(x['vc'].values()), x['sender']))
    
    raw_data = json.dumps({"vector_clock": vector_clock, "ledger": ledger}, ensure_ascii=False)
    f_cipher = Fernet(aes_key)
    encrypted_data = f_cipher.encrypt(raw_data.encode('utf-8'))
    
    with open(filename, 'wb') as f_out:
        f_out.write(encrypted_data)

def load_ledger(passphrase: str):
    """Giải mã file JSON vào RAM"""
    global ledger, vector_clock, aes_key
    filename = f"{MY_USERNAME}.json"
    aes_key = derive_key(passphrase)
    
    if os.path.exists(filename):
        try:
            with open(filename, 'rb') as f_in:
                encrypted_data = f_in.read()
            f_cipher = Fernet(aes_key)
            decrypted_data = f_cipher.decrypt(encrypted_data).decode('utf-8')
            data = json.loads(decrypted_data)
            ledger = data.get('ledger', [])
            vector_clock = data.get('vector_clock', {})
            print(f"[HỆ THỐNG] Đã giải mã thành công sổ cái của {MY_USERNAME}.")
            return True
        except Exception:
            print("[LỖI] Sai mật khẩu hoặc file dữ liệu bị hỏng!")
            return False
    else:
        print("[HỆ THỐNG] Không tìm thấy dữ liệu cũ, khởi tạo sổ cái mới.")
        return True

# --- HÀM BẢO MẬT RSA (SECURITY IN TRANSIT) ---

def generate_keys():
    global private_key, public_key_pem
    print("[HỆ THỐNG] Đang tạo cặp khóa RSA 2048-bit...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def encrypt_msg(message, pub_key_pem):
    pub_key = serialization.load_pem_public_key(pub_key_pem.encode('utf-8'))
    encrypted = pub_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_msg(enc_msg_b64):
    try:
        data = base64.b64decode(enc_msg_b64)
        return private_key.decrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode('utf-8')
    except: return "[Nội dung đã mã hóa]"

# --- LOGIC ĐỒNG BỘ & P2P ---

def sync_data(inc_ledger, inc_vc):
    global ledger, vector_clock
    with clock_lock:
        # Hợp nhất tin nhắn không trùng lặp
        current_sigs = {json.dumps(m, sort_keys=True) for m in ledger}
        for m in inc_ledger:
            if json.dumps(m, sort_keys=True) not in current_sigs:
                ledger.append(m)
        # Cập nhật Vector Clock: Max(local, remote)
        all_users = set(vector_clock.keys()) | set(inc_vc.keys())
        for u in all_users:
            vector_clock[u] = max(vector_clock.get(u, 0), inc_vc.get(u, 0))
        save_ledger()

def handle_p2p(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        payload = json.loads(data)
        sync_data(payload.get('ledger', []), payload.get('vector_clock', {}))
        
        sender = payload.get('sender')
        decrypted = decrypt_msg(payload.get('content'))
        print(f"\n<<< {sender} >>>: {decrypted}")
        print(f"Nhập lệnh > ", end="", flush=True)
    except: pass
    finally: conn.close()

def p2p_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', MY_P2P_PORT))
    s.listen(10)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_p2p, args=(conn, addr), daemon=True).start()

def send_chat(target, text):
    target = target.lower()
    if target not in PEER_LIST: return
    
    info = PEER_LIST[target]
    with clock_lock:
        vector_clock[MY_USERNAME] = vector_clock.get(MY_USERNAME, 0) + 1
        content_enc = encrypt_msg(text, info['public_key'])
        # Thêm vào Ledger cục bộ
        ledger.append({"sender": MY_USERNAME, "content": content_enc, "vc": dict(vector_clock)})
        save_ledger()
        
        payload = {
            "sender": MY_USERNAME, "content": content_enc,
            "vector_clock": dict(vector_clock), "ledger": ledger
        }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((info['ip'], info['p2p_port']))
        s.sendall(json.dumps(payload).encode('utf-8'))
        s.close()
    except: print("[LỖI] Không thể kết nối tới Peer.")

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    pwd = input(f"Nhập mật mã để mở khóa sổ cái {MY_USERNAME}: ")
    if not load_ledger(pwd): return
    
    MY_P2P_PORT = int(input("P2P Port: "))
    
    # Đăng ký với Discovery Server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({
            "command": "REGISTER", "username": MY_USERNAME,
            "p2p_port": MY_P2P_PORT, "public_key": public_key_pem
        }).encode('utf-8'))
        s.recv(1024); s.close()
    except: print("Server Offline!"); return

    threading.Thread(target=p2p_listener, daemon=True).start()

    while True:
        line = input("Nhập lệnh > ").strip()
        if not line: continue
        args = line.split(' ', 2)
        cmd = args[0].upper()

        if cmd == 'EXIT': break
        elif cmd == 'UPDATE':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps({"command": "GET_PEERS"}).encode('utf-8'))
            PEER_LIST = json.loads(s.recv(BUFFER_SIZE).decode('utf-8')).get('peers', {})
            s.close()
            print(f"[HỆ THỐNG] Đã cập nhật danh bạ.")
        elif cmd == 'PEERS':
            for u in PEER_LIST: 
                if u != MY_USERNAME: print(f"- {u}")
        elif cmd == 'CHAT' and len(args) == 3:
            send_chat(args[1], args[2])
        elif cmd == 'SHOW':
            print(f"\n--- SỔ CÁI ĐÃ GIẢI MÃ ({MY_USERNAME}) ---")
            for m in ledger:
                print(f"[{m['sender'].upper()}] {decrypt_msg(m['content'])}")

if __name__ == "__main__":
    main()