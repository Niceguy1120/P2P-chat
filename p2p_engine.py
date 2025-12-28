import os, json, base64, socket, threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class P2PEngine:
    def __init__(self):
        self.username = None
        self.ledger = []
        self.vector_clock = {}
        self.peer_list = {}
        self.lock = threading.Lock()
        # Tạo cặp khóa RSA cho node [cite: 40]
        self.private_key = rsa.generate_private_key(65537, 2048)
        self.pub_key_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.cipher = None

    def _get_key(self, password):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'p2p_salt', iterations=100000, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def authenticate(self, u, p):
        self.username = u
        filename = f"{u}.json"
        key = self._get_key(p)
        temp_cipher = Fernet(key)
        
        if os.path.exists(filename):
            try:
                with open(filename, 'rb') as f:
                    data = json.loads(temp_cipher.decrypt(f.read()).decode())
                self.ledger = data.get('ledger', [])
                self.vector_clock = data.get('vc', {u: 0})
                self.cipher = temp_cipher
                return True, "Đăng nhập thành công"
            except: return False, "Sai Passphrase!"
        else:
            self.vector_clock = {u: 0}
            self.cipher = temp_cipher
            self.save_to_json() # Lưu trữ cục bộ dưới dạng JSON mã hóa [cite: 15, 27]
            return True, "Tài khoản mới đã được tạo"

    def save_to_json(self):
        if not self.cipher: return
        data = {"ledger": self.ledger, "vc": self.vector_clock}
        with open(f"{self.username}.json", 'wb') as f:
            f.write(self.cipher.encrypt(json.dumps(data).encode()))

    def decrypt_msg(self, text):
        try:
            return self.private_key.decrypt(
                base64.b64decode(text), 
                padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            ).decode()
        except: return "[Lỗi giải mã]"

    def get_auto_port(self, start):
        for p in range(start, start + 100):
            with socket.socket() as s:
                if s.connect_ex(('localhost', p)) != 0: return p
        return None