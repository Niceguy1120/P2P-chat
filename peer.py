import socket
import threading
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
BUFFER_SIZE = 8192

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}

# --- BIẾN HỆ THỐNG PHÂN TÁN ---
lamport_clock = 0
clock_lock = threading.Lock() # Đảm bảo an toàn luồng khi cập nhật clock

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
    print("[HỆ THỐNG] Đã tạo khóa thành công.")

def encrypt_message(message, recipient_public_key_pem):
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
    encrypted = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message_b64):
    encrypted_data = base64.b64decode(encrypted_message_b64)
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode('utf-8')

def update_clock(received_clock=None):
    """Cập nhật Lamport Clock theo quy tắc Max(local, received) + 1"""
    global lamport_clock
    with clock_lock:
        if received_clock is not None:
            lamport_clock = max(lamport_clock, received_clock) + 1
        else:
            lamport_clock += 1
        return lamport_clock

def handle_p2p_connection(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        payload = json.loads(data)
        
        sender = payload.get('sender')
        msg_clock = payload.get('timestamp')
        
        # Cập nhật clock khi nhận tin
        current_l = update_clock(msg_clock)
        
        decrypted_content = decrypt_message(payload.get('content'))
        
        print(f"\n[BẢO MẬT] (Lamport: {msg_clock}) {sender}: {decrypted_content}")
        print(f"[HỆ THỐNG] Clock nội bộ cập nhật thành: {current_l}")
        print(f"Nhập lệnh > ", end="", flush=True)
    except Exception as e:
        print(f"\n[LỖI P2P NHẬN]: {e}")
    finally:
        conn.close()

def p2p_server_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('127.0.0.1', MY_P2P_PORT))
        s.listen(5)
        print(f"[HỆ THỐNG] Đang lắng nghe P2P tại 127.0.0.1:{MY_P2P_PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_p2p_connection, args=(conn, addr), daemon=True).start()
    except Exception as e:
        print(f"[LỖI KHỞI TẠO P2P]: {e}")

def send_p2p_message(recipient, content):
    recipient = recipient.lower()
    if recipient not in PEER_LIST:
        print(f"Không tìm thấy {recipient}. Hãy gõ UPDATE."); return
    
    info = PEER_LIST[recipient]
    try:
        # Cập nhật clock trước khi gửi
        current_l = update_clock()
        
        enc_msg = encrypt_message(content, info['public_key'])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((info['ip'], info['p2p_port']))
        
        # Gửi kèm Lamport Timestamp
        payload = {
            "sender": MY_USERNAME,
            "content": enc_msg,
            "timestamp": current_l
        }
        
        s.sendall(json.dumps(payload).encode('utf-8'))
        s.close()
        print(f"[CLIENT] Đã gửi (Clock: {current_l}) tới {recipient}.")
    except Exception as e:
        print(f"[LỖI GỬI]: {e}")

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    MY_P2P_PORT = int(input("P2P Port: "))

    # Đăng ký với Discovery Server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps({
            "command": "REGISTER", "username": MY_USERNAME, 
            "p2p_port": MY_P2P_PORT, "public_key": public_key_pem
        }).encode('utf-8'))
        s.recv(BUFFER_SIZE)
        s.close()
        print("*** ĐĂNG KÝ THÀNH CÔNG ***")
    except:
        print("Không thể kết nối Server!"); return

    threading.Thread(target=p2p_server_listener, daemon=True).start()

    while True:
        cmd_line = input("Nhập lệnh > ").strip()
        if not cmd_line: continue
        parts = cmd_line.split(' ', 2)
        cmd = parts[0].upper()

        if cmd == 'EXIT': break
        elif cmd == 'PEERS':
            for u in PEER_LIST:
                if u != MY_USERNAME: print(f"- {u}")
        elif cmd == 'UPDATE':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((SERVER_HOST, SERVER_PORT))
                s.sendall(json.dumps({"command": "GET_PEERS"}).encode('utf-8'))
                PEER_LIST = json.loads(s.recv(BUFFER_SIZE).decode('utf-8')).get('peers', {})
                s.close()
                print(f"[HỆ THỐNG] Đã cập nhật {len(PEER_LIST)} người dùng.")
            except: print("Lỗi cập nhật danh sách.")
        elif cmd == 'CHAT' and len(parts) == 3:
            send_p2p_message(parts[1], parts[2])

if __name__ == "__main__":
    main()