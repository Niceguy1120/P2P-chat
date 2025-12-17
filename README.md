# Cài Đặt và Chạy Demo với Conda

## Bước 1: Tạo Môi trường Conda

Bạn nên tạo một môi trường riêng biệt để cài đặt các dependency (mặc dù dự án này không cần dependency bên ngoài, đây vẫn là một thói quen tốt).

Mở Terminal hoặc Anaconda Prompt và chạy lệnh sau:

`# 1. Tạo môi trường mới tên là 'p2p-chat-env' với Python 3.10 (hoặc phiên bản bạn muốn)  conda create --name p2p-chat-env python=3.10 -y  # 2. Kích hoạt môi trường vừa tạo  conda activate p2p-chat-env`

Bây giờ bạn đang ở trong môi trường p2p-chat-env. Bạn sẽ thấy tên môi trường xuất hiện ở đầu dòng lệnh.

## Bước 2: Chuẩn bị Mã nguồn

Đảm bảo bạn đã lưu hai file mã nguồn đã cung cấp:

- [server.py]
- [peer.py]

Đặt cả hai file này vào cùng một thư mục (ví dụ: p2p_chat_project).

## Bước 3: Khởi chạy Discovery Server

Trong Terminal/Anaconda Prompt đang kích hoạt p2p-chat-env (hoặc mở một cửa sổ mới và kích hoạt lại):

Chạy Server:

`python server.py`

Bạn sẽ thấy thông báo:

`*** DISCOVERY SERVER đang lắng nghe trên 0.0.0.0:8888 ***`

## Bước 4: Khởi chạy Peers (Sử dụng các cửa sổ Terminal khác nhau)

Để demo chat P2P, bạn cần ít nhất hai cửa sổ Terminal khác (hoặc Anaconda Prompt) và đảm bảo mỗi cửa sổ đều đang kích hoạt p2p-chat-env.

### Peer 1 (Alice)

Mở Terminal/Anaconda Prompt thứ hai và kích hoạt môi trường:

`conda activate p2p-chat-env  python peer.py`

Nhập Username: Alice

Nhập P2P Port: 50001

Bạn sẽ thấy:

`[P2P Server] Đang lắng nghe trên [IP CỦA BẠN]:50001...`

### Peer 2 (Bob)

Mở Terminal/Anaconda Prompt thứ ba và kích hoạt môi trường:

`conda activate p2p-chat-env  python peer.py`

Nhập Username: Bob

Nhập P2P Port: 50002

Bạn sẽ thấy:

`[P2P Server] Đang lắng nghe trên [IP CỦA BẠN]:50002...`

## Bước 5: Kiểm tra và Chat

- Kiểm tra Server (Terminal 1): Server sẽ hiển thị thông báo đã nhận lệnh REGISTER từ cả Alice và Bob.
- Tại cửa sổ Bob: Gõ lệnh PEERS để xem Alice.
- Tại cửa sổ Bob: Gõ lệnh chat P2P:

`CHAT Alice Chào Alice! Conda hoạt động tốt!`

- Tại cửa sổ Alice: Bạn sẽ thấy tin nhắn trực tiếp xuất hiện.

## Thoát khỏi Môi trường Conda

Sau khi hoàn thành, bạn có thể tắt các Terminal. Để thoát khỏi môi trường conda:

` conda deactivate  ``` `
