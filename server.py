import socket
import threading
import json

HOST = '0.0.0.0'
PORT = 8888
BUFFER_SIZE = 8192 # Tăng buffer để nhận Public Key RSA

ACTIVE_PEERS = {} # {username: {"ip": ip, "p2p_port": port, "public_key": pk}}

def handle_client(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data: return
        request = json.loads(data)
        command = request.get('command')
        username = request.get('username', '').lower()

        if command == 'REGISTER':
            p2p_port = request.get('p2p_port')
            public_key = request.get('public_key')
            ACTIVE_PEERS[username] = {
                "ip": addr[0], 
                "p2p_port": p2p_port, 
                "public_key": public_key
            }
            print(f"[SERVER] Đã đăng ký: {username} ({addr[0]}:{p2p_port})")
            conn.sendall(json.dumps({"status": "OK"}).encode('utf-8'))

        elif command == 'GET_PEERS':
            conn.sendall(json.dumps({"status": "OK", "peers": ACTIVE_PEERS}).encode('utf-8'))

        elif command == 'LOGOUT':
            if username in ACTIVE_PEERS:
                del ACTIVE_PEERS[username]
                print(f"[SERVER] {username} đã thoát.")
            conn.sendall(json.dumps({"status": "OK"}).encode('utf-8'))

    except Exception as e:
        print(f"[SERVER LỖI]: {e}")
    finally:
        conn.close()

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"*** DISCOVERY SERVER ĐANG CHẠY TRÊN PORT {PORT} ***")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()