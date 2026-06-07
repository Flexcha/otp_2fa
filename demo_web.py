import os
import time
import sqlite3
import bcrypt
import pyotp
import secrets
import string
import qrcode
import io
import base64
from flask import Flask, render_template, request, session, redirect, url_for, flash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --- Configuration ---
DB_FILE = 'auth_web.db'
MASTER_KEY_ENV = os.environ.get('APP_MASTER_KEY', 'default_secret_key_32_bytes_long_!')
MASTER_KEY = MASTER_KEY_ENV.encode()[:32].ljust(32, b'\0')

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_TIME = 60
TIME_STEP = 30

# --- Database & Crypto Utilities ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0, lockout_until REAL DEFAULT 0, is_2fa_enabled BOOLEAN DEFAULT 0)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS otp_secrets (
        user_id INTEGER PRIMARY KEY, encrypted_secret BLOB NOT NULL, nonce BLOB NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, code_hash TEXT NOT NULL, is_used BOOLEAN DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS used_otps (
        user_id INTEGER, otp TEXT, timestamp REAL, PRIMARY KEY(user_id, otp))''')
    conn.commit()
    conn.close()

def encrypt_secret(secret: str) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    encrypted_secret = aesgcm.encrypt(nonce, secret.encode(), None)
    return encrypted_secret, nonce

def decrypt_secret(encrypted_secret: bytes, nonce: bytes) -> str:
    aesgcm = AESGCM(MASTER_KEY)
    decrypted_secret = aesgcm.decrypt(nonce, encrypted_secret, None)
    return decrypted_secret.decode()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_backup_codes(count=8, length=8) -> list[str]:
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(count)]

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for('register'))
            
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            flash("Username already exists.", "error")
            conn.close()
            return redirect(url_for('register'))
            
        hashed_pw = hash_password(password)
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        conn.close()
        
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))
        
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if not user:
            flash("Invalid username or password.", "error")
            conn.close()
            return redirect(url_for('login'))
            
        current_time = time.time()
        if current_time < user['lockout_until']:
            flash(f"Account locked. Try again in {int(user['lockout_until'] - current_time)}s.", "error")
            conn.close()
            return redirect(url_for('login'))
            
        if not verify_password(password, user['password_hash']):
            failed = user['failed_attempts'] + 1
            if failed >= MAX_FAILED_ATTEMPTS:
                conn.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?", 
                             (failed, current_time + LOCKOUT_TIME, user['id']))
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_TIME}s.", "error")
            else:
                conn.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, user['id']))
                flash("Invalid username or password.", "error")
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
            
        conn.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE id = ?", (user['id'],))
        conn.commit()
        conn.close()
        
        if user['is_2fa_enabled']:
            session['pending_2fa_user_id'] = user['id']
            session['pending_username'] = user['username']
            return redirect(url_for('login_2fa'))
        else:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
            
    return render_template("login.html")

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['pending_2fa_user_id']
    
    if request.method == 'POST':
        otp_input = request.form['otp'].strip()
        conn = get_db_connection()
        
        # Check Backup Code
        if len(otp_input) == 8:
            backup_codes = conn.execute("SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND is_used = 0", (user_id,)).fetchall()
            for row in backup_codes:
                if verify_password(otp_input, row['code_hash']):
                    conn.execute("UPDATE backup_codes SET is_used = 1 WHERE id = ?", (row['id'],))
                    conn.commit()
                    conn.close()
                    
                    session['user_id'] = user_id
                    session['username'] = session.pop('pending_username')
                    session.pop('pending_2fa_user_id')
                    return redirect(url_for('dashboard'))
            flash("Invalid or already used backup code.", "error")
            conn.close()
            return redirect(url_for('login_2fa'))
            
        # Check TOTP
        current_time = time.time()
        if conn.execute("SELECT timestamp FROM used_otps WHERE user_id = ? AND otp = ?", (user_id, otp_input)).fetchone():
            flash("This OTP has already been used. Please wait for a new one.", "error")
            conn.close()
            return redirect(url_for('login_2fa'))
            
        secret_data = conn.execute("SELECT encrypted_secret, nonce FROM otp_secrets WHERE user_id = ?", (user_id,)).fetchone()
        if not secret_data:
            flash("System Error: Secret key not found.", "error")
            conn.close()
            return redirect(url_for('login'))
            
        secret = decrypt_secret(secret_data['encrypted_secret'], secret_data['nonce'])
        totp = pyotp.TOTP(secret)
        
        if totp.verify(otp_input, valid_window=1):
            conn.execute("DELETE FROM used_otps WHERE timestamp < ?", (current_time - TIME_STEP * 2,))
            conn.execute("INSERT INTO used_otps (user_id, otp, timestamp) VALUES (?, ?, ?)", (user_id, otp_input, current_time))
            conn.commit()
            conn.close()
            
            session['user_id'] = user_id
            session['username'] = session.pop('pending_username')
            session.pop('pending_2fa_user_id')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid or expired authentication code.", "error")
            conn.close()
            return redirect(url_for('login_2fa'))
            
    return render_template("login_2fa.html")

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('login'))
        
    # Nơi đây bạn có thể tích hợp API gửi SMS/Email thực tế (VD: Twilio, SendGrid)
    flash("A new OTP has been sent to your registered email (Mockup feature).", "success")
    return redirect(url_for('login_2fa'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    user = conn.execute("SELECT is_2fa_enabled FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template("dashboard.html", is_2fa_enabled=user['is_2fa_enabled'])

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    username = session['username']
    
    conn = get_db_connection()
    user = conn.execute("SELECT is_2fa_enabled FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if user['is_2fa_enabled']:
        conn.close()
        flash("2FA is already enabled.", "error")
        return redirect(url_for('dashboard'))
        
    if request.method == 'GET':
        secret = pyotp.random_base32()
        session['setup_secret'] = secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureAuthWeb")
        
        from qrcode.image.pil import PilImage
        qr = qrcode.make(uri, image_factory=PilImage)
        buf = io.BytesIO()
        qr.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        conn.close()
        return render_template("setup_2fa.html", secret=secret, qr_b64=qr_b64)
        
    if request.method == 'POST':
        otp_input = request.form['otp'].strip()
        secret = session.get('setup_secret')
        
        if not secret:
            conn.close()
            return redirect(url_for('setup_2fa'))
            
        totp = pyotp.TOTP(secret)
        if totp.verify(otp_input, valid_window=1):
            encrypted_secret, nonce = encrypt_secret(secret)
            conn.execute("INSERT OR REPLACE INTO otp_secrets (user_id, encrypted_secret, nonce) VALUES (?, ?, ?)", 
                         (user_id, encrypted_secret, nonce))
            
            backup_codes = generate_backup_codes()
            for code in backup_codes:
                code_hash = hash_password(code)
                conn.execute("INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)", (user_id, code_hash))
                
            conn.execute("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            
            session.pop('setup_secret', None)
            session['backup_codes'] = backup_codes
            return redirect(url_for('show_backup_codes'))
        else:
            conn.close()
            flash("Invalid authentication code. Try again.", "error")
            return redirect(url_for('setup_2fa'))

@app.route('/backup-codes')
def show_backup_codes():
    if 'user_id' not in session or 'backup_codes' not in session:
        return redirect(url_for('dashboard'))
        
    codes = session.pop('backup_codes')
    return render_template("backup_codes.html", codes=codes)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    print("Bắt đầu chạy Server Web Demo...")
    print("Truy cập: http://127.0.0.1:5050")
    app.run(debug=True, host='127.0.0.1', port=5050)
