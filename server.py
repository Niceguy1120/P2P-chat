# server.py (Cập nhật lưu trữ Public Key)
import socket
import threading
import json

HOST = '0.0.0.0'
PORT = 8888
BUFFER_SIZE = 4096 # Tăng buffer vì Public Key khá dài

ACTIVE_PEERS = {} # {username: {"ip": ip, "p2p_port": port, "public_key": pk_str}}

def handle_client(conn, addr):
    ip_client = addr[0]
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        request = json.loads(data)
        command = request.get('command')

        if command == 'REGISTER':
            username = request.get('username')
            p2p_port = request.get('p2p_port')
            public_key = request.get('public_key')
            
            if username and p2p_port and public_key:
                ACTIVE_PEERS[username] = {
                    "ip": ip_client, 
                    "p2p_port": p2p_port, 
                    "public_key": public_key
                }
                print(f"[SERVER] Đã đăng ký {username} kèm Public Key.")
                conn.sendall(json.dumps({"status": "OK"}).encode('utf-8'))

        elif command == 'GET_PEERS':
            # Trả về toàn bộ thông tin bao gồm cả Public Key
            response = {"status": "OK", "peers": ACTIVE_PEERS}
            conn.sendall(json.dumps(response).encode('utf-8'))

        elif command == 'LOGOUT':
            username = request.get('username')
            if username in ACTIVE_PEERS:
                del ACTIVE_PEERS[username]
                print(f"[SERVER] {username} đã thoát.")
            conn.sendall(json.dumps({"status": "OK"}).encode('utf-8'))

    except Exception as e:
        print(f"[SERVER] Lỗi: {e}")
    finally:
        conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    print(f"*** DISCOVERY SERVER (BẢO MẬT RSA) ĐANG CHẠY TRÊN PORT {PORT} ***")
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()