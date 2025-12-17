# server.py

import socket
import threading
import json

# Cấu hình Server
HOST = '0.0.0.0' # Lắng nghe trên mọi interface
PORT = 8888 
BUFFER_SIZE = 1024

# Từ điển lưu trữ các Peers đang hoạt động: {username: (ip, p2p_port)}
ACTIVE_PEERS = {}

def handle_client(conn, addr):
    """Xử lý kết nối đến từ một Peer (client)"""
    
    ip_client = addr[0]
    
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data:
            return

        request = json.loads(data)
        command = request.get('command')
        
        print(f"\n[SERVER] Nhận lệnh '{command}' từ {ip_client}")

        if command == 'REGISTER':
            # Lệnh: Đăng ký Peer mới
            username = request.get('username')
            p2p_port = request.get('p2p_port')
            
            if username and p2p_port:
                ACTIVE_PEERS[username] = (ip_client, p2p_port)
                print(f"[SERVER] Peer mới: {username} - ({ip_client}:{p2p_port})")
                
                response = {"status": "OK", "message": "Đăng ký thành công."}
                conn.sendall(json.dumps(response).encode('utf-8'))
            else:
                response = {"status": "ERROR", "message": "Thiếu thông tin đăng ký."}
                conn.sendall(json.dumps(response).encode('utf-8'))

        elif command == 'GET_PEERS':
            # Lệnh: Lấy danh sách Peers
            peer_list = []
            for user, (ip, port) in ACTIVE_PEERS.items():
                peer_list.append({"username": user, "ip": ip, "p2p_port": port})
            
            response = {"status": "OK", "peers": peer_list}
            print(f"[SERVER] Trả về danh sách {len(peer_list)} peers.")
            conn.sendall(json.dumps(response).encode('utf-8'))

        elif command == 'LOGOUT':
            # Lệnh: Đăng xuất/Xóa Peer
            username_to_remove = None
            for username, (ip, port) in list(ACTIVE_PEERS.items()):
                if ip == ip_client:
                    username_to_remove = username
                    break
            
            if username_to_remove and username_to_remove in ACTIVE_PEERS:
                del ACTIVE_PEERS[username_to_remove]
                print(f"[SERVER] Xóa Peer: {username_to_remove}")
                response = {"status": "OK", "message": "Đăng xuất thành công."}
                conn.sendall(json.dumps(response).encode('utf-8'))
            else:
                response = {"status": "ERROR", "message": "Không tìm thấy Peer để xóa."}
                conn.sendall(json.dumps(response).encode('utf-8'))


    except json.JSONDecodeError:
        print(f"[SERVER] Lỗi định dạng JSON từ {ip_client}")
    except Exception as e:
        print(f"[SERVER] Lỗi xử lý kết nối từ {ip_client}: {e}")
    finally:
        conn.close()

def start_server():
    """Khởi động Server Đăng ký"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"*** DISCOVERY SERVER đang lắng nghe trên {HOST}:{PORT} ***")
        
        while True:
            conn, addr = server_socket.accept()
            # Mỗi kết nối được xử lý bởi một luồng mới
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            
    except Exception as e:
        print(f"[SERVER] Lỗi khi khởi động server: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()