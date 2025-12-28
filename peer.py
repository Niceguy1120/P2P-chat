import socket, threading, json, base64
from flask import Flask, render_template, request, jsonify
from p2p_engine import P2PEngine
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__, template_folder='.')
engine = P2PEngine()

P2P_PORT = engine.get_auto_port(5000)
WEB_PORT = engine.get_auto_port(8000)

@app.route('/')
def index():
    return render_template('index.html', user="", p2p_port=P2P_PORT, web_port=WEB_PORT)

@app.route('/login', methods=['POST'])
def login():
    d = request.json
    ok, msg = engine.authenticate(d['username'], d['passphrase'])
    if ok:
        threading.Thread(target=register_discovery).start() # Đăng ký node [cite: 10]
        return jsonify({"status": "ok"})
    return jsonify({"status": "err", "message": msg})

def register_discovery():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('127.0.0.1', 8888))
            s.send(json.dumps({"command": "REGISTER", "username": engine.username, "ip": "127.0.0.1", "p2p_port": P2P_PORT, "public_key": engine.pub_key_pem}).encode())
    except: pass

@app.route('/get_peers')
def g_peers():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(('127.0.0.1', 8888))
            s.send(json.dumps({"command": "GET_PEERS"}).encode())
            res = json.loads(s.recv(65536).decode())
            engine.peer_list = {u: i for u, i in res['peers'].items() if u != engine.username}
    except: pass
    return jsonify(list(engine.peer_list.keys()))

@app.route('/get_messages')
def g_msgs():
    # Giải mã toàn bộ ledger để hiển thị lên UI [cite: 11]
    return jsonify([{"sender": m['sender'], "content": engine.decrypt_msg(m['content']), "vc": m['vc']} for m in engine.ledger])

@app.route('/send_chat', methods=['POST'])
def s_chat():
    d = request.json
    target, msg_text = d['target'], d['message']
    if target in engine.peer_list:
        peer = engine.peer_list[target]
        with engine.lock:
            # 1. Tăng Vector Clock [cite: 40]
            engine.vector_clock[engine.username] = engine.vector_clock.get(engine.username, 0) + 1
            current_vc = dict(engine.vector_clock)

            # 2. Mã hóa cho người nhận 
            pk_target = serialization.load_pem_public_key(peer['public_key'].encode())
            enc_target = base64.b64encode(pk_target.encrypt(
                msg_text.encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            )).decode()

            # 3. Mã hóa cho chính mình để hiển thị lại được (Dùng Public Key của chính mình)
            pk_me = serialization.load_pem_public_key(engine.pub_key_pem.encode())
            enc_me = base64.b64encode(pk_me.encrypt(
                msg_text.encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            )).decode()

            payload_to_send = {"sender": engine.username, "type": "CHAT", "content": enc_target, "vc": current_vc}
            payload_to_save = {"sender": engine.username, "type": "CHAT", "content": enc_me, "vc": current_vc}
            
            engine.ledger.append(payload_to_save)
            engine.save_to_json() # Nhất quán cuối cùng [cite: 50, 51]
        
        threading.Thread(target=lambda: (s:=socket.socket(), s.connect((peer['ip'], peer['p2p_port'])), s.send(json.dumps(payload_to_send).encode()), s.close())).start()
    return jsonify({"status": "ok"})

def p2p_listen():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', P2P_PORT))
    s.listen(10) # Lắng nghe kết nối TCP [cite: 23, 35]
    while True:
        c, _ = s.accept()
        raw = c.recv(65536).decode()
        if raw:
            data = json.loads(raw)
            with engine.lock:
                engine.ledger.append(data)
                # Cập nhật Vector Clock đồng bộ [cite: 40]
                for k, v in data['vc'].items(): engine.vector_clock[k] = max(engine.vector_clock.get(k, 0), v)
                engine.save_to_json()
        c.close()

if __name__ == "__main__":
    print(f"\n[HỆ THỐNG] P2P Port: {P2P_PORT} | Web Port: {WEB_PORT}")
    print(f"[HỆ THỐNG] TRUY CẬP: http://127.0.0.1:{WEB_PORT}\n")
    threading.Thread(target=p2p_listen, daemon=True).start()
    app.run(port=WEB_PORT, debug=False, use_reloader=False)