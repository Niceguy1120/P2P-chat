import socket, threading, json, base64
from flask import Flask, render_template, request, jsonify
from p2p_engine import P2PEngine
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__, template_folder='.')
engine = P2PEngine()
P2P_PORT = engine.get_auto_port(5000)
WEB_PORT = engine.get_auto_port(8000)
SERVER_ADDR = ('127.0.0.1', 8888)

@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    d = request.json
    ok, msg = engine.authenticate(d['username'], d['passphrase'])
    if ok: return jsonify({"status": "ok"})
    return jsonify({"status": "err", "message": msg})

def register():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(SERVER_ADDR)
            s.send(json.dumps({"command":"REGISTER", "username":engine.username, "ip":"127.0.0.1", "p2p_port":P2P_PORT, "public_key":engine.pub_key_pem}).encode())
    except: pass

def background_sync():
    """Tự động đồng bộ và đăng ký lại khi Server sống dậy"""
    while True:
        if engine.username:
            try:
                register()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect(SERVER_ADDR)
                    s.send(json.dumps({"command": "GET_PEERS"}).encode())
                    res = json.loads(s.recv(65536).decode())
                    new_peers = {u: i for u, i in res['peers'].items() if u != engine.username}
                    with engine.lock:
                        engine.peer_list.update(new_peers)
                        engine.save()
            except: pass
        threading.Event().wait(10)

@app.route('/get_peers')
def g_peers(): return jsonify(list(engine.peer_list.keys()))

@app.route('/get_messages')
def g_msgs():
    return jsonify([{"sender":m['sender'], "target":m.get('target',''), "content":engine.decrypt_msg(m['content']), "vc":m['vc']} for m in engine.ledger])

@app.route('/send_chat', methods=['POST'])
def s_chat():
    d = request.json
    target, msg_text = d['target'], d['message']
    if target in engine.peer_list:
        peer = engine.peer_list[target]
        with engine.lock:
            engine.vector_clock[engine.username] = engine.vector_clock.get(engine.username, 0) + 1
            # Mã hóa cho người nhận
            pk_t = serialization.load_pem_public_key(peer['public_key'].encode())
            enc_t = base64.b64encode(pk_t.encrypt(msg_text.encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))).decode()
            # Mã hóa cho chính mình xem lại
            pk_me = serialization.load_pem_public_key(engine.pub_key_pem.encode())
            enc_me = base64.b64encode(pk_me.encrypt(msg_text.encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))).decode()
            
            payload_s = {"sender": engine.username, "type": "CHAT", "content": enc_t, "vc": dict(engine.vector_clock)}
            payload_v = {"sender": engine.username, "target": target, "content": enc_me, "vc": dict(engine.vector_clock)}
            engine.ledger.append(payload_v)
            engine.save()
            
        threading.Thread(target=lambda: (s:=socket.socket(), s.connect((peer['ip'], peer['p2p_port'])), s.send(json.dumps(payload_s).encode()), s.close())).start()
    return jsonify({"status": "ok"})

def listen():
    s = socket.socket()
    s.bind(('0.0.0.0', P2P_PORT)); s.listen(10)
    while True:
        c, _ = s.accept()
        raw = c.recv(65536).decode()
        if raw:
            data = json.loads(raw)
            with engine.lock:
                data['target'] = engine.username
                engine.ledger.append(data)
                for k,v in data['vc'].items(): engine.vector_clock[k] = max(engine.vector_clock.get(k,0), v)
                engine.save()
        c.close()

if __name__ == "__main__":
    print(f"\n[HỆ THỐNG] TRUY CẬP TẠI: http://127.0.0.1:{WEB_PORT}\n")
    threading.Thread(target=listen, daemon=True).start()
    threading.Thread(target=background_sync, daemon=True).start()
    app.run(port=WEB_PORT, debug=False, use_reloader=False)