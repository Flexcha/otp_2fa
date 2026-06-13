import os
import time
import sqlite3
import bcrypt
import pyotp
import secrets
import string
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Cấu hình hằng số ---
DB_FILE = 'auth.db'
# Master key để mã hóa Secret Key (AES-256 yêu cầu khóa 32 bytes)
# Trong thực tế nên lưu trữ an toàn trong biến môi trường
MASTER_KEY_ENV = os.environ.get('APP_MASTER_KEY', 'default_secret_key_32_bytes_long_!')
MASTER_KEY = MASTER_KEY_ENV.encode()[:32].ljust(32, b'\0')

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_TIME = 60 # giây
TIME_STEP = 30 # giây (Chuẩn TOTP)

# --- Quản lý Database ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Bảng người dùng
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until REAL DEFAULT 0,
            is_2fa_enabled BOOLEAN DEFAULT 0
        )
    ''')
    # Bảng lưu secret key (đã mã hóa)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS otp_secrets (
            user_id INTEGER PRIMARY KEY,
            encrypted_secret BLOB NOT NULL,
            nonce BLOB NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # Bảng lưu mã dự phòng
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            code_hash TEXT NOT NULL,
            is_used BOOLEAN DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # Bảng lưu các OTP đã sử dụng để chống Replay Attack
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS used_otps (
            user_id INTEGER,
            otp TEXT,
            timestamp REAL,
            PRIMARY KEY(user_id, otp)
        )
    ''')
    conn.commit()
    conn.close()

# --- Tiện ích Mã hóa (Crypto Utilities) ---
def encrypt_secret(secret: str) -> tuple[bytes, bytes]:
    """Mã hóa secret key bằng AES-256-GCM"""
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12) # GCM khuyến cáo dùng nonce 12 bytes
    encrypted_secret = aesgcm.encrypt(nonce, secret.encode(), None)
    return encrypted_secret, nonce

def decrypt_secret(encrypted_secret: bytes, nonce: bytes) -> str:
    """Giải mã secret key"""
    aesgcm = AESGCM(MASTER_KEY)
    decrypted_secret = aesgcm.decrypt(nonce, encrypted_secret, None)
    return decrypted_secret.decode()

def hash_password(password: str) -> str:
    """Băm mật khẩu sử dụng bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Xác minh mật khẩu với mã băm"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_backup_codes(count=8, length=8) -> list[str]:
    """Sinh mã dự phòng ngẫu nhiên (entropy cao)"""
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(count)]

# --- Logic Nghiệp vụ (Business Logic) ---
def register_user():
    print("\n--- ĐĂNG KÝ TÀI KHOẢN ---")
    username = input("Tên đăng nhập: ")
    password = getpass.getpass("Mật khẩu: ") # Ẩn ký tự nhập vào
    
    if len(password) < 6:
        print("[-] Mật khẩu phải có ít nhất 6 ký tự!")
        return False
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print("[-] Tên đăng nhập đã tồn tại!")
            return False

        hashed_pw = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        print("[+] Đăng ký tài khoản thành công!")
        return True
    finally:
        conn.close()

def setup_2fa(username):
    print("\n--- CÀI ĐẶT BẢO MẬT 2FA ---")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, is_2fa_enabled FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            print("[-] Người dùng không tồn tại!")
            return False
        
        user_id, is_2fa_enabled = user
        if is_2fa_enabled:
            print("[-] Tài khoản đã kích hoạt 2FA!")
            return False

        # Sinh ngẫu nhiên secret key 20-byte (160 bit) dạng base32
        secret = pyotp.random_base32()
        
        # Tạo đường dẫn URI chuẩn để tạo QR Code
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="HệThốngBảoMật")
        
        print("\nĐể kích hoạt 2FA, hãy sử dụng ứng dụng như Google Authenticator hoặc Microsoft Authenticator.")
        print(f"1. Chuỗi Secret Key (nhập thủ công nếu không quét được): {secret}")
        print(f"2. Link tạo QR Code (dùng để quét): {uri}")
        
        # Yêu cầu xác thực lần đầu để chính thức kích hoạt
        otp_input = input("\nNhập mã OTP đầu tiên để xác nhận kích hoạt: ")
        totp = pyotp.TOTP(secret)
        
        # Cho phép cửa sổ lệch 1 bước (+-30s)
        if totp.verify(otp_input, valid_window=1): 
            # Mã hóa và lưu secret key vào DB
            encrypted_secret, nonce = encrypt_secret(secret)
            cursor.execute("INSERT OR REPLACE INTO otp_secrets (user_id, encrypted_secret, nonce) VALUES (?, ?, ?)", 
                           (user_id, encrypted_secret, nonce))
            
            # Sinh và lưu mã dự phòng
            backup_codes = generate_backup_codes()
            print("\n[!] QUAN TRỌNG: Hãy lưu lại các mã dự phòng sau ở nơi an toàn. Mỗi mã chỉ dùng 1 lần!")
            print("-----------------------------------------")
            for code in backup_codes:
                print(f" - {code}")
                code_hash = hash_password(code)
                cursor.execute("INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)", (user_id, code_hash))
            print("-----------------------------------------")
            
            # Cập nhật trạng thái
            cursor.execute("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?", (user_id,))
            conn.commit()
            print("\n[+] Kích hoạt 2FA thành công!")
            return True
        else:
            print("[-] Mã OTP không chính xác. Hủy kích hoạt 2FA.")
            return False
            
    finally:
        conn.close()

def disable_2fa(username):
    print("\n--- HỦY BẢO MẬT 2FA ---")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, is_2fa_enabled FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            print("[-] Người dùng không tồn tại!")
            return False
        
        user_id, is_2fa_enabled = user
        if not is_2fa_enabled:
            print("[-] Tài khoản chưa kích hoạt 2FA!")
            return False

        confirm = input("Bạn có chắc chắn muốn hủy 2FA không? (y/n): ")
        if confirm.lower() == 'y':
            cursor.execute("UPDATE users SET is_2fa_enabled = 0 WHERE id = ?", (user_id,))
            cursor.execute("DELETE FROM otp_secrets WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
            conn.commit()
            print("[+] Hủy 2FA thành công!")
            return True
        else:
            print("[-] Đã hủy thao tác.")
            return False
    finally:
        conn.close()

def login():
    print("\n--- ĐĂNG NHẬP ---")
    username = input("Tên đăng nhập: ")
    password = getpass.getpass("Mật khẩu: ")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, password_hash, failed_attempts, lockout_until, is_2fa_enabled FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            # Thông báo lỗi chung chung (không phân biệt sai user hay sai pass) -> chống enumeration
            print("[-] Sai tên đăng nhập hoặc mật khẩu!")
            return None
            
        user_id, password_hash, failed_attempts, lockout_until, is_2fa_enabled = user
        
        current_time = time.time()
        # Kiểm tra Rate Limiting
        if current_time < lockout_until:
            print(f"[-] Tài khoản đang bị khóa. Thử lại sau {int(lockout_until - current_time)} giây.")
            return None
            
        # Xác minh mật khẩu
        if not verify_password(password, password_hash):
            failed_attempts += 1
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                new_lockout = current_time + LOCKOUT_TIME
                cursor.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?", (failed_attempts, new_lockout, user_id))
                print(f"[-] Sai mật khẩu quá nhiều lần. Tài khoản tạm khóa {LOCKOUT_TIME} giây.")
            else:
                cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed_attempts, user_id))
                print(f"[-] Sai tên đăng nhập hoặc mật khẩu! (Còn {MAX_FAILED_ATTEMPTS - failed_attempts} lần thử)")
            conn.commit()
            return None
            
        # Đăng nhập bước 1 thành công -> Xóa bộ đếm
        cursor.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE id = ?", (user_id,))
        conn.commit()
        
        # Nếu chưa bật 2FA
        if not is_2fa_enabled:
            print("[+] Đăng nhập thành công! (Tài khoản chưa bật 2FA)")
            return username
            
        # Bước 2: Xác thực 2FA
        print("\n--- XÁC THỰC HAI BƯỚC (2FA) ---")
        otp_input = input("Nhập mã OTP 6 số (hoặc mã dự phòng 8 ký tự): ").strip()
        
        # Xử lý nếu dùng mã dự phòng (Backup Codes)
        if len(otp_input) == 8:
            cursor.execute("SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND is_used = 0", (user_id,))
            backup_codes = cursor.fetchall()
            for code_id, code_hash in backup_codes:
                if verify_password(otp_input, code_hash):
                    # Mã hợp lệ -> Đánh dấu đã dùng
                    cursor.execute("UPDATE backup_codes SET is_used = 1 WHERE id = ?", (code_id,))
                    conn.commit()
                    print("[+] Đăng nhập thành công bằng mã dự phòng!")
                    return username
            print("[-] Mã dự phòng không hợp lệ hoặc đã được sử dụng!")
            return None
            
        # Chống Replay Attack: Kiểm tra mã OTP đã dùng trong cửa sổ thời gian gần chưa
        cursor.execute("SELECT timestamp FROM used_otps WHERE user_id = ? AND otp = ?", (user_id, otp_input))
        if cursor.fetchone():
            print("[-] Mã OTP này đã được sử dụng để đăng nhập. Vui lòng đợi mã mới!")
            return None
            
        # Lấy và giải mã Secret Key
        cursor.execute("SELECT encrypted_secret, nonce FROM otp_secrets WHERE user_id = ?", (user_id,))
        secret_data = cursor.fetchone()
        if not secret_data:
            print("[-] Lỗi hệ thống: Không tìm thấy secret key.")
            return None
            
        encrypted_secret, nonce = secret_data
        secret = decrypt_secret(encrypted_secret, nonce)
        totp = pyotp.TOTP(secret)
        
        # Xác minh OTP hợp lệ (+- 1 bước ~ 30s)
        if totp.verify(otp_input, valid_window=1):
            # Xóa các OTP cũ trong DB cho sạch
            cursor.execute("DELETE FROM used_otps WHERE timestamp < ?", (current_time - TIME_STEP * 2,))
            # Lưu lại OTP đã dùng để chống Replay Attack
            cursor.execute("INSERT INTO used_otps (user_id, otp, timestamp) VALUES (?, ?, ?)", (user_id, otp_input, current_time))
            conn.commit()
            print("[+] Đăng nhập thành công!")
            return username
        else:
            print("[-] Mã OTP không chính xác hoặc đã hết hạn!")
            return None

    finally:
        conn.close()

# --- Giao diện Dòng lệnh (CLI) ---
def main():
    init_db()
    while True:
        print("\n==================================")
        print(" HỆ THỐNG XÁC THỰC BẢO MẬT ĐA LỚP ")
        print("==================================")
        print("1. Đăng ký")
        print("2. Đăng nhập")
        print("3. Thoát")
        choice = input("Lựa chọn của bạn: ")
        
        if choice == '1':
            register_user()
        elif choice == '2':
            user = login()
            if user:
                while True:
                    print(f"\n>> TRANG QUẢN TRỊ (Xin chào {user}) <<")
                    print("1. Cài đặt 2FA")
                    print("2. Hủy 2FA")
                    print("3. Đăng xuất")
                    sub_choice = input("Lựa chọn của bạn: ")
                    if sub_choice == '1':
                        setup_2fa(user)
                    elif sub_choice == '2':
                        disable_2fa(user)
                    elif sub_choice == '3':
                        print("[+] Đã đăng xuất.")
                        break
                    else:
                        print("[-] Lựa chọn không hợp lệ.")
        elif choice == '3':
            print("Thoát chương trình. Tạm biệt!")
            break
        else:
            print("[-] Lựa chọn không hợp lệ. Vui lòng nhập số từ 1 đến 3.")

if __name__ == '__main__':
    main()
