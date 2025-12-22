import socket
import threading
import json
import base64
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
BUFFER_SIZE = 8192

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}

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

def get_my_ip():
    """Ưu tiên trả về localhost để test trên 1 máy dễ dàng hơn"""
    return '127.0.0.1'

def handle_p2p_connection(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        payload = json.loads(data)
        sender = payload.get('sender')
        decrypted_content = decrypt_message(payload.get('content'))
        print(f"\n[BẢO MẬT] Nhận tin từ {sender}: {decrypted_content}")
        print(f"Nhập lệnh > ", end="", flush=True)
    except Exception as e:
        print(f"\n[LỖI P2P NHẬN]: {e}")
    finally:
        conn.close()

def p2p_server_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((get_my_ip(), MY_P2P_PORT))
        s.listen(5)
        print(f"[HỆ THỐNG] Đang lắng nghe P2P tại {get_my_ip()}:{MY_P2P_PORT}")
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
        enc_msg = encrypt_message(content, info['public_key'])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3) # Timeout 3 giây để tránh treo
        s.connect((info['ip'], info['p2p_port']))
        s.sendall(json.dumps({"sender": MY_USERNAME, "content": enc_msg}).encode('utf-8'))
        s.close()
        print(f"[CLIENT] Đã gửi tin mã hóa tới {recipient}.")
    except Exception as e:
        print(f"[LỖI GỬI]: {e} (Kiểm tra Port {info['p2p_port']} của {recipient})")

def main():
    global MY_USERNAME, MY_P2P_PORT, PEER_LIST
    generate_keys()
    MY_USERNAME = input("Username: ").strip().lower()
    MY_P2P_PORT = int(input("P2P Port: "))

    # Đăng ký
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
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
            for u, info in PEER_LIST.items():
                if u != MY_USERNAME: print(f"- {u} ({info['ip']}:{info['p2p_port']})")
        elif cmd == 'UPDATE':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps({"command": "GET_PEERS"}).encode('utf-8'))
            PEER_LIST = json.loads(s.recv(BUFFER_SIZE).decode('utf-8')).get('peers', {})
            s.close()
            print(f"[HỆ THỐNG] Đã cập nhật {len(PEER_LIST)} người dùng.")
        elif cmd == 'CHAT' and len(parts) == 3:
            send_p2p_message(parts[1], parts[2])

if __name__ == "__main__":
    main()