import socket
import threading
import json
import sys

# Lưu trữ danh bạ: {username: {ip, p2p_port, public_key}}
directory = {}
dir_lock = threading.Lock()

def handle_client(conn, addr):
    try:
        conn.settimeout(5.0) # Tránh treo luồng nếu client ngắt kết nối đột ngột
        data = conn.recv(65536).decode('utf-8')
        if not data: return
        
        request = json.loads(data)
        command = request.get("command")
        
        if command == "REGISTER":
            user = request.get("username")
            with dir_lock:
                directory[user] = {
                    "ip": addr[0],
                    "p2p_port": request.get("p2p_port"),
                    "public_key": request.get("public_key")
                }
            print(f"[REGISTER] User '{user}' đăng ký thành công từ {addr[0]}")
            conn.sendall(json.dumps({"status": "OK"}).encode('utf-8'))
            
        elif command == "GET_PEERS":
            with dir_lock:
                response = {"peers": directory}
            conn.sendall(json.dumps(response).encode('utf-8'))
            
    except Exception as e:
        print(f"[LỖI] Xử lý client {addr}: {e}")
    finally:
        conn.close()

def start_server():
    host = '0.0.0.0' # Lắng nghe trên tất cả các card mạng
    port = 8888
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Cho phép sử dụng lại Port ngay lập tức sau khi tắt server
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((host, port))
        server_sock.listen(20)
        print(f"*** DISCOVERY SERVER ĐANG CHẠY TRÊN PORT {port} ***")
        print("--- Nhấn CTRL+C để dừng Server ---")
        
        while True:
            # Thiết lập timeout cho accept để Python có thể nhận tín hiệu KeyboardInterrupt
            server_sock.settimeout(1.0)
            try:
                conn, addr = server_sock.accept()
                # Chạy mỗi client trên một luồng daemon (tự chết khi server tắt)
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[HỆ THỐNG] Đang đóng Server theo yêu cầu...")
    finally:
        server_sock.close()
        sys.exit(0)

if __name__ == "__main__":
    start_server()