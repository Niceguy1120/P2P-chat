# peer.py

import socket
import threading
import json
import time

# Cấu hình Server Đăng ký
SERVER_HOST = '127.0.0.1'  # Thay đổi nếu Server ở máy khác
SERVER_PORT = 8888 
BUFFER_SIZE = 1024

# Biến toàn cục của Peer
MY_USERNAME = ""
MY_P2P_PORT = 0
PEER_LIST = {}  # {username: {"ip": ip, "p2p_port": port}}

def get_my_ip():
    """Tìm IP nội bộ của máy (cách đơn giản)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Không cần kết nối thực tế, chỉ cần gọi connect() để lấy IP
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def connect_to_server(request):
    """Gửi yêu cầu đến Discovery Server"""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((SERVER_HOST, SERVER_PORT))
        
        server_socket.sendall(json.dumps(request).encode('utf-8'))
        
        response_data = server_socket.recv(BUFFER_SIZE).decode('utf-8')
        response = json.loads(response_data)
        
        server_socket.close()
        return response
    except Exception as e:
        print(f"[- LỖI MẠNG -] Không thể kết nối đến Discovery Server: {e}")
        return None

# --- CHỨC NĂNG SERVER P2P (LẮNG NGHE) ---

def handle_p2p_connection(conn, addr):
    """Xử lý kết nối P2P đến từ Peers khác"""
    try:
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        if not data:
            return

        message = json.loads(data)
        sender = message.get('sender', 'Không rõ')
        content = message.get('content', 'Không có nội dung')
        
        print(f"\n<<< {sender} >>>: {content}")
        print(f"Nhập lệnh > ", end="", flush=True) # In lại prompt
        
    except json.JSONDecodeError:
        print("\n[LỖI P2P] Nhận dữ liệu không phải JSON.")
    except Exception as e:
        print(f"\n[LỖI P2P] Xử lý kết nối P2P: {e}")
    finally:
        conn.close()

def p2p_server_listener():
    """Khởi động Server P2P để lắng nghe tin nhắn"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Lắng nghe trên IP thực của máy và cổng P2P đã chọn
        server_socket.bind((get_my_ip(), MY_P2P_PORT))
        server_socket.listen(5)
        print(f"[P2P Server] Đang lắng nghe trên {get_my_ip()}:{MY_P2P_PORT}...")
        
        while True:
            conn, addr = server_socket.accept()
            # Xử lý mỗi tin nhắn P2P trong một luồng riêng
            thread = threading.Thread(target=handle_p2p_connection, args=(conn, addr))
            thread.start()
            
    except Exception as e:
        # Nếu cổng đã được sử dụng hoặc lỗi khác
        print(f"[- LỖI -] Không thể khởi động P2P Server trên cổng {MY_P2P_PORT}: {e}")
        # Gửi lệnh LOGOUT để xóa thông tin khỏi Server nếu lỗi
        logout_request = {"command": "LOGOUT", "username": MY_USERNAME}
        connect_to_server(logout_request)
        exit(1) # Thoát ứng dụng

# --- CHỨC NĂNG CLIENT (GỬI TIN NHẮN) ---

def send_p2p_message(recipient, content):
    """Gửi tin nhắn trực tiếp đến Peer đích"""
    if recipient not in PEER_LIST:
        print(f"[LỖI] Peer '{recipient}' không có trong danh sách hoặc chưa hoạt động.")
        return

    peer_info = PEER_LIST[recipient]
    
    try:
        # Tạo kết nối socket mới đến Peer đích
        p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Sử dụng IP và Port P2P của Peer đích
        dest_ip = peer_info['ip']
        dest_port = peer_info['p2p_port']
        
        print(f"[CLIENT] Đang kết nối đến {recipient} ({dest_ip}:{dest_port})...")
        p2p_socket.connect((dest_ip, dest_port))

        # Đóng gói tin nhắn
        message = {
            "sender": MY_USERNAME,
            "recipient": recipient,
            "content": content
        }
        
        p2p_socket.sendall(json.dumps(message).encode('utf-8'))
        print(f"[CLIENT] Đã gửi tin nhắn đến {recipient}.")
        
    except Exception as e:
        print(f"[LỖI P2P] Không thể gửi tin nhắn đến {recipient}: {e}")
    finally:
        if 'p2p_socket' in locals():
            p2p_socket.close()

# --- CHỨC NĂNG CHÍNH VÀ GIAO DIỆN ---

def get_peer_list():
    """Lấy danh sách Peers mới nhất từ Discovery Server"""
    global PEER_LIST
    request = {"command": "GET_PEERS"}
    response = connect_to_server(request)
    
    if response and response.get('status') == 'OK':
        PEER_LIST = {}
        for peer in response.get('peers', []):
            PEER_LIST[peer['username']] = peer
        print("\n[CẬP NHẬT] Danh sách Peers đã được làm mới.")
    else:
        print("[CẬP NHẬT] Không thể lấy danh sách Peers.")

def display_help():
    """Hiển thị hướng dẫn sử dụng"""
    print("\n--- LỆNH HỆ THỐNG ---")
    print("PEERS        : Hiển thị danh sách Peers đang hoạt động.")
    print("CHAT [USER] [MSG] : Gửi tin nhắn P2P trực tiếp đến Peer đó.")
    print("UPDATE       : Cập nhật danh sách Peers từ Server.")
    print("EXIT         : Thoát ứng dụng và đăng xuất.")
    print("------------------------")
    
def main_menu():
    """Vòng lặp chính của ứng dụng"""
    
    while True:
        try:
            command_line = input(f"Nhập lệnh > ")
            parts = command_line.split(' ', 2)
            command = parts[0].upper()

            if command == 'EXIT':
                break
            
            elif command == 'PEERS':
                if not PEER_LIST:
                    print("[INFO] Danh sách rỗng. Hãy dùng lệnh UPDATE.")
                else:
                    print("\n--- DANH SÁCH PEERS ĐANG HOẠT ĐỘNG ---")
                    for user, info in PEER_LIST.items():
                        # Không in thông tin của chính mình
                        if user != MY_USERNAME:
                            print(f"- {user} ({info['ip']}:{info['p2p_port']})")
                    print("--------------------------------------")

            elif command == 'UPDATE':
                get_peer_list()
                
            elif command == 'CHAT':
                if len(parts) >= 3:
                    recipient = parts[1]
                    message_content = parts[2]
                    send_p2p_message(recipient, message_content)
                else:
                    print("[LỖI] Cú pháp: CHAT [Username đích] [Tin nhắn]")

            elif command == 'HELP':
                display_help()
                
            else:
                print(f"[LỖI] Lệnh không hợp lệ: {command}. Gõ 'HELP' để xem hướng dẫn.")

        except EOFError: # Xử lý Ctrl+D
            break
        except Exception as e:
            print(f"[LỖI] Xảy ra lỗi trong vòng lặp chính: {e}")

    # Xử lý khi thoát
    logout_request = {"command": "LOGOUT", "username": MY_USERNAME}
    connect_to_server(logout_request)
    print(f"\nĐã đăng xuất {MY_USERNAME}. Ứng dụng P2P Chat kết thúc.")

def initialize_peer():
    """Khởi tạo Peer: Nhập thông tin và đăng ký"""
    global MY_USERNAME, MY_P2P_PORT

    while not MY_USERNAME:
        MY_USERNAME = input("Nhập Username của bạn: ").strip()
    
    while True:
        try:
            p2p_port_str = input("Nhập P2P Port lắng nghe (ví dụ: 50001): ").strip()
            MY_P2P_PORT = int(p2p_port_str)
            if 1024 <= MY_P2P_PORT <= 65535:
                break
            else:
                print("Port phải nằm trong khoảng 1024 - 65535.")
        except ValueError:
            print("Port phải là số nguyên.")
            
    my_ip = get_my_ip()
    print(f"IP nội bộ của bạn: {my_ip}")
    
    # 1. Đăng ký với Server
    register_request = {
        "command": "REGISTER", 
        "username": MY_USERNAME, 
        "p2p_port": MY_P2P_PORT
    }
    
    response = connect_to_server(register_request)
    
    if not response or response.get('status') != 'OK':
        print(f"[- LỖI -] Đăng ký với Server thất bại: {response.get('message', 'Lỗi không xác định')}")
        exit(1)
        
    print(f"*** Đăng ký thành công! Chào mừng {MY_USERNAME}! ***")
    
    # 2. Khởi động luồng Server P2P
    p2p_thread = threading.Thread(target=p2p_server_listener, daemon=True)
    p2p_thread.start()
    
    # 3. Lấy danh sách Peers lần đầu
    get_peer_list()
    
    # 4. Bắt đầu Menu chính (luồng Client)
    main_menu()

if __name__ == "__main__":
    initialize_peer()