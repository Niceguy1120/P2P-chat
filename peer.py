import socket
import threading
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
BUFFER_SIZE = 16384 # Tăng buffer để gửi kèm cả Ledger

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}

# --- BIẾN DISTRIBUTED LEDGER & CLOCK ---
vector_clock = {}
ledger = [] # Danh sách các dict: {"sender":..., "content":..., "vc":...}
clock_lock = threading.Lock()

private_key = None
public_key_pem = ""

def generate_keys():
    global private_key, public_key_pem
    print("[HỆ THỐNG] Đang tạo cặp khóa RSA 2048-bit...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def encrypt_message(message, recipient_public_key_pem):
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
    encrypted = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message_b64):
    try:
        encrypted_data = base64.b64decode(encrypted_message_b64)
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode('utf-8')
    except: return "[Tin nhắn mã hóa cho người khác]"

# --- THUẬT TOÁN ĐỒNG BỘ SỔ CÁI (LEDGER) ---

def compare_vc(vc1, vc2):
    """So sánh 2 Vector Clock: trả về -1 nếu vc1 < vc2, 1 nếu vc1 > vc2, 0 nếu đồng thời"""
    less = False
    greater = False
    all_keys = set(vc1.keys()) | set(vc2.keys())
    for k in all_keys:
        v1 = vc1.get(k, 0)
        v2 = vc2.get(k, 0)
        if v1 < v2: less = True
        if v1 > v2: greater = True
    
    if less and not greater: return -1
    if greater and not less: return 1
    return 0

def sort_ledger():
    """Sắp xếp Ledger theo quy tắc Vector Clock + Tiêu chuẩn phụ (Username)"""
    global ledger
    def sort_key(item):
        # Tính tổng các giá trị trong VC để có một độ ưu tiên cơ bản
        return sum(item['vc'].values()), item['sender']
    
    ledger.sort(key=sort_key)

def save_ledger():
    """Lưu sổ cái vào file [username].json"""
    sort_ledger()
    filename = f"{MY_USERNAME}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump({"vector_clock": vector_clock, "ledger": ledger}, f, ensure_ascii=False, indent=4)

def load_ledger():
    """Tải sổ cái từ file khi khởi động"""
    global ledger, vector_clock
    filename = f"{MY_USERNAME}.json"
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
            ledger = data.get('ledger', [])
            vector_clock = data.get('vector_clock', {})
        print(f"[HỆ THỐNG] Đã tải sổ cái từ {filename}")

def sync_ledger(incoming_ledger, incoming_vc):
    """Hợp nhất sổ cái nhận được vào sổ cái cục bộ"""
    global ledger, vector_clock
    with clock_lock:
        # Hợp nhất tin nhắn (tránh trùng lặp)
        existing_msgs = {json.dumps(m, sort_keys=True) for m in ledger}
        for msg in incoming_ledger:
            if json.dumps(msg, sort_keys=True) not in existing_msgs:
                ledger.append(msg)
        
        # Cập nhật Vector Clock cục bộ
        for user, count in incoming_vc.items():
            vector_clock[user] = max(vector_clock.get(user, 0), count)
        
        save_ledger()

# --- MẠNG P2P ---

def handle_p2p_connection(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        payload = json.loads(data)
        
        sender = payload.get('sender')
        inc_vc = payload.get('vector_clock')
        inc_ledger = payload.get('ledger', [])
        
        # Đồng bộ Ledger
        sync_ledger(inc_ledger, inc_vc)
        
        # Giải mã tin nhắn mới nhất nếu dành cho mình
        raw_content = payload.get('content')
        if raw_content:
            decrypted = decrypt_message(raw_content)
            print(f"\n<<< {sender} >>>: {decrypted}")
        
        print(f"Nhập lệnh > ", end="", flush=True)
    except Exception as e:
        print(f"\n[LỖI NHẬN]: {e}")
    finally:
        conn.close()

def p2p_server_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', MY_P2P_PORT))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_p2p_connection, args=(conn, addr), daemon=True).start()

def send_p2p_message(recipient, content):
    recipient = recipient.lower()
    if recipient not in PEER_LIST: return
    
    info = PEER_LIST[recipient]
    with clock_lock:
        vector_clock[MY_USERNAME] = vector_clock.get(MY_USERNAME, 0) + 1
        enc_msg = encrypt_message(content, info['public_key'])
        
        # Thêm tin nhắn của mình vào Ledger trước khi gửi
        new_entry = {"sender": MY_USERNAME, "content": enc_msg, "vc": dict(vector_clock)}
        ledger.append(new_entry)
        save_ledger()

        payload = {
            "sender": MY_USERNAME,
            "content": enc_msg,
            "vector_clock": dict(vector_clock),
            "ledger": ledger # Gửi toàn bộ Ledger để đồng bộ
        }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((info['ip'], info['p2p_port']))
        s.sendall(json.dumps(payload).encode('utf-8'))
        s.close()
        print(f"[HỆ THỐNG] Đã gửi và đồng bộ sổ cái tới {recipient}.")
    except: print("[LỖI] Không thể kết nối tới Peer.")

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    MY_P2P_PORT = int(input("P2P Port: "))
    
    load_ledger()
    if MY_USERNAME not in vector_clock: vector_clock[MY_USERNAME] = 0

    # Đăng ký với Server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({"command":"REGISTER", "username":MY_USERNAME, "p2p_port":MY_P2P_PORT, "public_key":public_key_pem}).encode('utf-8'))
        s.recv(BUFFER_SIZE); s.close()
    except: print("Server Offline!"); return

    threading.Thread(target=p2p_server_listener, daemon=True).start()

    while True:
        cmd_line = input("Nhập lệnh > ").strip()
        parts = cmd_line.split(' ', 2)
        cmd = parts[0].upper()

        if cmd == 'EXIT': break
        elif cmd == 'PEERS':
            for u in PEER_LIST: print(f"- {u}")
        elif cmd == 'UPDATE':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps({"command": "GET_PEERS"}).encode('utf-8'))
            PEER_LIST = json.loads(s.recv(BUFFER_SIZE).decode('utf-8')).get('peers', {})
            s.close()
            print(f"[HỆ THỐNG] Đã cập nhật danh sách.")
        elif cmd == 'CHAT' and len(parts) == 3:
            send_p2p_message(parts[1], parts[2])
        elif cmd == 'SHOW': # Lệnh mới để xem sổ cái cục bộ
            print(f"\n--- SỔ CÁI CỦA {MY_USERNAME.upper()} ---")
            for m in ledger:
                sender = m['sender']
                content = decrypt_message(m['content'])
                print(f"[{sender}] {content} (VC: {m['vc']})")

if __name__ == "__main__":
    main()