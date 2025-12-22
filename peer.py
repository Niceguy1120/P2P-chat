# peer.py (Cập nhật RSA Encryption)
import socket
import threading
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
BUFFER_SIZE = 4096

MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}

# --- QUẢN LÝ KHÓA RSA ---
private_key = None
public_key_pem = ""

def generate_keys():
    global private_key, public_key_pem
    print("[HỆ THỐNG] Đang tạo cặp khóa RSA 2048-bit...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Chuyển Public Key sang định dạng chuỗi để gửi qua mạng
    public_key_pem = public_key.public_key_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    print("[HỆ THỐNG] Đã tạo khóa thành công.")

def encrypt_message(message, recipient_public_key_pem):
    """Mã hóa tin nhắn bằng khóa công khai của người nhận"""
    recipient_public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8')
    )
    encrypted = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode Base64 để gửi qua JSON dễ dàng
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message_b64):
    """Giải mã bằng khóa bí mật của chính mình"""
    encrypted_data = base64.b64decode(encrypted_message_b64)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

# --- MẠNG P2P ---

def handle_p2p_connection(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        payload = json.loads(data)
        
        # Giải mã tin nhắn nhận được
        encrypted_content = payload.get('content')
        sender = payload.get('sender')
        
        try:
            decrypted_content = decrypt_message(encrypted_content)
            print(f"\n[BẢO MẬT] Nhận tin nhắn đã mã hóa từ {sender}")
            print(f"<<< {sender} >>>: {decrypted_content}")
        except:
            print(f"\n[LỖI] Không thể giải mã tin nhắn từ {sender}!")
            
        print(f"Nhập lệnh > ", end="", flush=True)
    except Exception as e:
        print(f"\n[LỖI P2P Server]: {e}")
    finally:
        conn.close()

def send_p2p_message(recipient, content):
    if recipient not in PEER_LIST:
        print("Người dùng không tồn tại.")
        return
    
    recipient_info = PEER_LIST[recipient]
    try:
        # 1. Mã hóa tin nhắn trước khi gửi
        encrypted_msg = encrypt_message(content, recipient_info['public_key'])
        
        # 2. Gửi qua Socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((recipient_info['ip'], recipient_info['p2p_port']))
        s.sendall(json.dumps({"sender": MY_USERNAME, "content": encrypted_msg}).encode('utf-8'))
        s.close()
        print(f"[CLIENT] Đã mã hóa và gửi tin đến {recipient}.")
    except Exception as e:
        print(f"[LỖI CLIENT]: {e}")

# --- PHẦN CÒN LẠI GIỐNG FILE CŨ NHƯNG CẬP NHẬT BIẾN ---
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('10.255.255.255', 1)); IP = s.getsockname()[0]
    except: IP = '127.0.0.1'
    finally: s.close()
    return IP

def connect_to_server(request):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(json.dumps(request).encode('utf-8'))
        resp = json.loads(s.recv(BUFFER_SIZE).decode('utf-8'))
        s.close()
        return resp
    except: return None

def get_peer_list():
    global PEER_LIST
    resp = connect_to_server({"command": "GET_PEERS"})
    if resp and resp.get('status') == 'OK':
        PEER_LIST = resp.get('peers', {})
        print(f"[INFO] Đã cập nhật danh sách {len(PEER_LIST)} peers.")

def p2p_server_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((get_my_ip(), MY_P2P_PORT))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_p2p_connection, args=(conn, addr)).start()

def main():
    global MY_USERNAME, MY_P2P_PORT
    generate_keys() # Tự tạo khóa khi khởi động
    
    MY_USERNAME = input("Username: ").strip()
    MY_P2P_PORT = int(input("P2P Port: "))
    
    # Gửi cả Public Key khi đăng ký
    resp = connect_to_server({
        "command": "REGISTER", 
        "username": MY_USERNAME, 
        "p2p_port": MY_P2P_PORT,
        "public_key": public_key_pem
    })
    
    if not resp or resp.get('status') != 'OK':
        print("Đăng ký thất bại!"); return

    threading.Thread(target=p2p_server_listener, daemon=True).start()
    get_peer_list()

    while True:
        cmd_line = input("Nhập lệnh > ")
        parts = cmd_line.split(' ', 2)
        cmd = parts[0].upper()
        if cmd == 'EXIT': break
        elif cmd == 'PEERS': 
            for u in PEER_LIST: print(f"- {u}")
        elif cmd == 'UPDATE': get_peer_list()
        elif cmd == 'CHAT' and len(parts) == 3:
            send_p2p_message(parts[1], parts[2])

if __name__ == "__main__":
    main()