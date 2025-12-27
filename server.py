import socket
import threading
import json
import sys

directory = {}
dir_lock = threading.Lock()

def handle_client(conn, addr):
    try:
        conn.settimeout(5.0)
        data = conn.recv(65536).decode('utf-8')
        if not data: return
        
        request = json.loads(data)
        command = request.get("command")
        
        if command == "REGISTER":
            user = request.get("username")
            with dir_lock:
                directory[user] = {
                    "ip": request.get("ip", addr[0]), # Ưu tiên IP LAN từ client
                    "p2p_port": request.get("p2p_port"),
                    "public_key": request.get("public_key")
                }
            print(f"[REGISTER] '{user}' tại {directory[user]['ip']}:{request.get('p2p_port')}")
            conn.sendall(json.dumps({"status": "OK"}).encode('utf-8'))
            
        elif command == "GET_PEERS":
            with dir_lock:
                response = {"peers": directory}
            conn.sendall(json.dumps(response).encode('utf-8'))
            
    except Exception as e:
        print(f"[LỖI] {addr}: {e}")
    finally:
        conn.close()

def start_server():
    host = '0.0.0.0'
    port = 8888
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((host, port))
        server_sock.listen(20)
        print(f"*** DISCOVERY SERVER RUNNING ON PORT {port} ***")
        while True:
            server_sock.settimeout(1.0)
            try:
                conn, addr = server_sock.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout: continue
    except KeyboardInterrupt:
        print("\n[HỆ THỐNG] Đang dừng Server...")
    finally:
        server_sock.close()
        sys.exit(0)

if __name__ == "__main__":
    start_server()