Dưới đây là file README.md chuyên nghiệp, được thiết kế để bạn có thể dán trực tiếp vào thư mục đồ án. Nội dung tập trung vào cách cài đặt, vận hành và các kịch bản test để gây ấn tượng với giảng viên.

P2P Enterprise Chat System
==========================

Đây là hệ thống trò chuyện phân tán (Peer-to-Peer) được thiết kế cho môi trường mạng nội bộ doanh nghiệp. Hệ thống tích hợp các cơ chế bảo mật nâng cao, tính nhất quán dữ liệu và khả năng tự phục hồi khi máy chủ danh bạ (Discovery Server) gặp sự cố.

🚀 Tính năng nổi bật
--------------------

*   **Kiến trúc Hybrid P2P:** Kết hợp Discovery Server và UDP Broadcast để tìm kiếm người dùng.
    
*   **Bảo mật đa tầng:**
    
    *   **RSA-2048:** Mã hóa tin nhắn trên đường truyền (End-to-End Encryption).
        
    *   **AES-256 (Fernet):** Mã hóa toàn bộ sổ cái (Ledger) khi lưu trữ trên ổ cứng.
        
    *   **PBKDF2:** Bảo vệ sổ cái bằng Passphrase cá nhân.
        
*   **Đồng bộ dữ liệu thông minh:**
    
    *   **Vector Clock:** Duy trì quan hệ nhân quả và thứ tự tin nhắn.
        
    *   **Gossip Protocol & Delta Sync:** Tự động đồng bộ các tin nhắn còn thiếu, tối ưu hóa băng thông cho nhóm đông người (đã test với quy mô 20 nodes).
        
*   **Khả năng chịu lỗi (Fault Tolerance):** \* **Offline Messaging:** Tự động lưu và gửi lại tin nhắn khi người nhận online trở lại.
    
    *   **Self-healing:** Tự động sử dụng danh bạ local hoặc Broadcast LAN nếu Server chết.
        

🛠 Cài đặt
----------

### 1\. Yêu cầu hệ thống

*   Python 3.10 trở lên.
    
*   Cài đặt môi trường thông qua file environment.yml (khuyên dùng Conda):
    

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   conda env create -f environment.yml  conda activate p2p-chat-env   `

Hoặc cài đặt thủ công qua pip:

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   pip install cryptography   `

### 2\. Cấu trúc file

*   server.py: Máy chủ danh bạ (Discovery Server).
    
*   peer.py: Ứng dụng chat dành cho người dùng.
    
*   checker.py: Công cụ kiểm toán (Audit) để kiểm tra tính nhất quán của Sổ cái.
    

📖 Hướng dẫn sử dụng
--------------------

### Bước 1: Khởi động Server

Chạy máy chủ danh bạ trước để các Peer có thể tìm thấy nhau:

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   python server.py   `

### Bước 2: Khởi động các Peer

Mở các terminal mới cho từng người dùng (ví dụ: Alice và Bob).**Lưu ý:** Mỗi người dùng trên cùng một máy phải sử dụng một **P2P Port** khác nhau.

Bash

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Terminal 1 (Alice)  python peer.py  # Nhập Username: alice  # Nhập Passphrase: (mật khẩu bất kỳ để mã hóa file chat)  # Nhập P2P Port: 5001  # Terminal 2 (Bob)  python peer.py  # Nhập Username: bob  # Nhập Passphrase: (mật khẩu bất kỳ)  # Nhập P2P Port: 5002   `

### Bước 3: Các lệnh trong ứng dụng

*   UPDATE: Cập nhật danh sách người dùng mới nhất từ Server hoặc qua mạng LAN.
    
*   PEERS: Xem danh sách những người đang online.
    
*   CHAT \[username\] \[nội dung\]: Gửi tin nhắn mã hóa.
    
*   HISTORY: Xem lịch sử trò chuyện (chỉ hiển thị các tin nhắn bạn có quyền đọc).
    
*   EXIT: Thoát ứng dụng và lưu dữ liệu.