<<<<<<< HEAD
# Hệ Thống Xác Thực 2 Lớp (2FA System)

Dự án này là một hệ thống xác thực bảo mật đa lớp được xây dựng bằng Python, minh hoạ cách tích hợp phương thức xác thực hai bước (2FA) theo chuẩn TOTP (Time-Based One-Time Password) kết hợp với các cơ chế bảo mật nâng cao. Dự án này được thiết kế dựa trên một tài liệu đặc tả hệ thống chuẩn mực.

## Tính năng nổi bật
1. **Xác thực 2 lớp (2FA):** Hỗ trợ chuẩn TOTP, tương thích hoàn toàn với Google Authenticator và Microsoft Authenticator. Tự động sinh mã QR để quét dễ dàng.
2. **Mã hóa an toàn:**
   - Mật khẩu người dùng được băm (hash) an toàn bằng thuật toán `bcrypt`.
   - Secret Key của người dùng (dùng để sinh mã TOTP) được mã hóa bằng chuẩn `AES-256-GCM` trước khi lưu vào Database.
3. **Mã dự phòng (Backup Codes):** Hệ thống cấp phát mã dự phòng (đã được băm an toàn) dùng một lần để cứu hộ tài khoản trong trường hợp mất thiết bị xác thực.
4. **Phòng chống Replay Attack:** Hệ thống lưu trữ và vô hiệu hoá các mã OTP đã được sử dụng thành công trong khoảng cửa sổ thời gian (±30s) để ngăn chặn việc sử dụng lại mã cũ.
5. **Rate Limiting:** Khóa tài khoản tạm thời tự động (ví dụ: khóa 60s) nếu người dùng nhập sai mật khẩu quá số lần cho phép (mặc định 3 lần) nhằm chống lại tấn công Brute-force.
6. **Đa giao diện:** Cung cấp cả ứng dụng Web (Flask + Bootstrap 5) và ứng dụng Dòng lệnh (CLI).

## 📂 Cấu trúc dự án
- `demo_web.py`: Ứng dụng Web hoàn chỉnh sử dụng Web Framework Flask, tích hợp giao diện Bootstrap 5 đẹp mắt, gọn gàng, có đầy đủ các màn hình luồng xử lý thực tế.
- `auth_system.py`: Phiên bản chạy hoàn toàn trên giao diện dòng lệnh (Terminal/CLI) dành cho việc kiểm thử logic và nghiệp vụ phía backend một cách nhanh chóng.
- `requirements.txt`: Danh sách các thư viện Python phục vụ hệ thống.
- `templates/`: Thư mục chứa giao diện HTML cho bản Web (`base.html`, `login.html`, `register.html`,...).

## Hướng dẫn Cài đặt & Chạy thử nghiệm

### 1. Cài đặt các thư viện phụ thuộc
Đảm bảo bạn đang ở môi trường ảo (virtual environment) của dự án, sau đó chạy lệnh sau để tải các thư viện cần thiết:
```bash
pip install -r requirements.txt
```
*(Các thư viện chính bao gồm: `Flask`, `pyotp`, `bcrypt`, `cryptography`, `qrcode`, `pillow`)*

### 2. Chạy Giao diện Web (Khuyên dùng)
Khởi chạy server Flask bằng lệnh:
```bash
python demo_web.py
```
Sau đó mở trình duyệt và truy cập vào địa chỉ: **http://127.0.0.1:5050**

### 3. Chạy Giao diện Dòng lệnh (CLI)
Nếu bạn chỉ muốn kiểm tra luồng logic chạy trên giao diện chữ (Terminal):
```bash
python auth_system.py
```

## Lưu ý về Môi trường Thực tế (Production)
- Hệ thống sử dụng SQLite (`auth.db` và `auth_web.db`) để dễ dàng demo. Khi lên thực tế, bạn có thể dễ dàng chuyển đổi sang PostgreSQL hay MySQL.
- Ứng dụng hiện tại sử dụng hằng số `MASTER_KEY` mặc định. Ở môi trường triển khai thực tế, bạn **bắt buộc** phải thay đổi và truyền biến khóa mã hóa (Secret Key AES-256) qua biến môi trường (Environment Variable `APP_MASTER_KEY`).
- Server Flask hiện tại chạy ở chế độ phát triển (Debug mode). Cần dùng một WSGI Server thực thụ như Gunicorn để chạy Producton.
=======
# otp_2fa
btl an toàn bảo mật thông tin
>>>>>>> 3f232bdd03ac2f3c07c2f9e9857595b71017bc0e
