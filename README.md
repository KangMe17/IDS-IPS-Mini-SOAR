# Hệ thống IDS/IPS sử dụng mã nguồn mở

## 📋 Tổng Quan Dự án

Dự án này cung cấp giải pháp tự động hóa bảo mật cho các hệ thống mạng, cho phép:
- **Giám sát** các cảnh báo bảo mật từ Suricata (EVE JSON format)
- **Phân tích** sự kiện dựa trên các rules được cấu hình
- **Phản ứng tự động** (chặn IP, cách ly và thông báo)
- **Quản lý** các hành động bảo mật qua API

## 📁 Cấu trúc Dự Án

```
.
├── README.md              # Tài liệu tổng thể (file này)
├── docs/                  # Tài liệu chi tiết
│   ├── BaoCaoTongKet.pdf  # Báo cáo tổng kết dự án
│   ├── kientrucmang.jpg   # Sơ đồ kiến trúc mạng
│   └── luongxuly.jpg      # Sơ đồ luồng xử lý
└── src/                   # Mã nguồn
    ├── README.md          # Tài liệu chi tiết Mini-SOAR
    ├── mini_soar.py       # Engine chính (single-file)
    ├── config.yaml        # File cấu hình mẫu
    └── requirements.txt   # Phụ thuộc Python
```

## 🚀 Bắt Đầu Nhanh

### Yêu Cầu
- Python 3.8+
- Quyền root (nếu muốn tương tác firewall)
- Suricata IDS/IPS đang chạy

### Cài Đặt

1. **Clone repo** (nếu chưa có):
```bash
git clone <repo-url> tieuluan
cd tieuluan
```

2. **Tạo virtual environment**:
```bash
# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. **Cài đặt phụ thuộc**:
```bash
cd src
pip install -r requirements.txt
```

4. **Cấu hình** (xem `src/config.yaml`):
   - Thay đường dẫn `eve_log` tới Suricata log của bạn
   - Cấu hình rules phản ứng
   - Thiết lập thông báo (Telegram, Email)
   - Cấu hình whitelist/ignore list

### Chạy Engine

```bash
cd src
python3 mini_soar.py --config "config.yaml"
```

**Chế độ test** (không chặn thực):
```bash
python3 mini_soar.py --config "config.yaml" --dry-run
```

## 💡 Tính Năng Chính

✅ **Giám sát Suricata Events**
- Theo dõi file log `eve.json` với hỗ trợ log rotation
- Xử lý sự kiện theo thời gian thực

✅ **Rules Engine Linh Hoạt**
- Cấu hình rules qua YAML
- Hỗ trợ các hành động: block, quarantine, TTL tùy chỉnh

✅ **Chặn/Cách Ly Tự động**
- Hỗ trợ **nftables** (hiện đại) và **iptables** (fallback)
- TTL theo luật hoặc mặc định

✅ **Thông Báo Đa Kênh**
- Telegram notifications
- Email notifications
- Log file

✅ **Persistence & Quản Lý**
- Lưu trữ sự kiện trong SQLite
- API quản lý (gỡ ban IP, xem lịch sử)
- Tự động gỡ ban khi TTL hết

## 📖 Tài Liệu Chi Tiết

Để hiểu thêm về Mini-SOAR engine, vui lòng xem:
- **[src/README.md](src/README.md)** - Tài liệu chi tiết Mini-SOAR
- **docs/kientrucmang.jpg** - Sơ đồ kiến trúc mạng
- **docs/luongxuly.jpg** - Sơ đồ luồng xử lý
- **docs/BaoCaoTongKet.pdf** - Báo cáo tổng kết

## ⚙️ Cấu Hình Cơ Bản

Chỉnh sửa `src/config.yaml`:

```yaml
# Suricata EVE log
eve_log: "/var/log/suricata/eve.json"

# Database
db_path: "/var/lib/mini_soar/mini_soar.db"

# Firewall
use_nft: true          # Dùng nftables
ban_ttl: 3600          # Chặn 1 giờ
unban_check_interval: 30

# Whitelist (không chặn)
whitelist:
  - "127.0.0.1"
  - "192.168.20.0/24"

# Rules
rules:
  - name: "SQL Injection Block"
    keywords: ["SQL"]
    action: "block"
    ttl: 7200
    
  - name: "Quarantine Malware"
    keywords: ["MALWARE"]
    action: "quarantine"
    ttl: 86400
```

Xem `src/config.yaml` để cấu hình đầy đủ.

## 🔌 API Quản Lý

Mini-SOAR cung cấp API HTTP trên cổng `9000` (tuỳ chỉnh):

**Gỡ ban IP**:
```bash
curl "http://127.0.0.1:9000/api/unban?ip=1.2.3.4"
```

## 🔒 Bảo Mật & Quyền Hạn

⚠️ **Quan trọng**:
- Chạy với quyền root để tương tác firewall (`nft`/`iptables`)
- Không commit token/mật khẩu thực vào repo
- Sử dụng environment variables hoặc secrets management
- Giới hạn quyền truy cập API

## 🛠️ Troubleshooting

| Vấn đề | Giải pháp |
|--------|----------|
| Lỗi module `yaml` hoặc `requests` | `pip install -r requirements.txt` |
| Lệnh firewall không hoạt động | Kiểm tra quyền root, `nft`/`iptables` cài đặt |
| Không tìm thấy log file | Kiểm tra đường dẫn `eve_log`, quyền đọc |
| Lỗi database | Kiểm tra quyền ghi vào `db_path` |

## 📝 Các Bảng Database

Mini-SOAR sử dụng SQLite với các bảng:
- **incidents** - Sự kiện phát hiện được
- **actions** - Hành động đã thực thi
- **bans** - Danh sách IP bị chặn

