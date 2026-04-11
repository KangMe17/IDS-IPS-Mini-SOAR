# Mini-SOAR

Một SOAR engine rất nhẹ (single-file) để phản ứng nhanh dựa trên log Suricata (EVE JSON).

**Mô tả ngắn:**
- `mini_soar.py` theo dõi file log `eve.json`, phát hiện alert theo rules trong cấu hình, lưu sự kiện vào SQLite và thực thi hành động (block IP, quarantine) qua nftables/iptables. Có thông báo qua Telegram và Email.

**Tính năng chính**
- Theo dõi log Suricata (EVE JSON) với hỗ trợ log rotation.
- Rules engine cấu hình được (block, quarantine, ttl).
- Hỗ trợ chặn bằng `nftables` (ưu tiên) hoặc `iptables` (fallback).
- Thông báo qua Telegram và Email.
- Persistence bằng SQLite (db_path trong cấu hình).

**Yêu cầu**
- Python 3.8+
- Các package trong `requirements.txt`: PyYAML, requests
- Quyền root nếu muốn tương tác với firewall (`nft`/`iptables`).

Cài đặt nhanh:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Hoặc trên Windows (PowerShell):

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Cấu hình**
- File cấu hình mẫu: `config.yaml`.
- Một số trường quan trọng:
	- `eve_log`: đường dẫn tới `eve.json` của Suricata.
	- `db_path`: nơi lưu SQLite DB.
	- `use_nft`: True để dùng nftables, False để dùng iptables.
	- `ban_ttl`: TTL mặc định cho lệnh block (giây).
	- `unban_check_interval`: chu kỳ kiểm tra gỡ ban (giây).
	- `whitelist`: danh sách IP/Subnet sẽ không bị chặn.
	- `ignore_keywords`: nếu signature chứa từ trong danh sách này thì sẽ bỏ qua.
	- `rules`: danh sách luật với `name`, `keywords`, `action`, `ttl`, `quarantine`, v.v.
	- `telegram` và `email`: cấu hình notify (token, chat_id, smtp...).

Lưu ý: file mẫu hiện có token Telegram và mật khẩu SMTP ví dụ — hãy thay thế và bảo mật thông tin này.

**Chạy chương trình**
- Chạy với cấu hình:

```bash
python3 mini_soar.py --config "config.yaml"
```

- Chế độ test (không thực thi lệnh firewall):

```bash
python3 mini_soar.py --config "config.yaml" --dry-run
```

**API quản lý**
- Mini-SOAR khởi API nhỏ lắng nghe cổng `http_api_port` (mặc định 9000). Ví dụ để gỡ ban:

```bash
curl "http://127.0.0.1:9000/api/unban?ip=1.2.3.4"
```

**Cấu trúc DB & log**
- DB SQLite chứa bảng `incidents`, `actions`, `bans`.
- Log mặc định viết ra console và file `/var/log/mini_soar.log` (có thể tuỳ chỉnh trong mã).

**Bảo mật & Quyền hạn**
- Để chặn/quarantine thực sự, cần quyền root và `nft`/`iptables` cài đặt sẵn.
- Đừng lưu token hoặc mật khẩu thực trong repo công khai. Sử dụng secrets hoặc quyền truy cập giới hạn.

**Khắc phục sự cố**
- Nếu module `yaml` hoặc `requests` chưa cài, cài bằng `pip install -r requirements.txt`.
- Nếu không có `nft`, chương trình tự chuyển sang `iptables` fallback.
- Kiểm tra quyền ghi vào `db_path` và quyền truy cập tới `eve_log`.

**Tệp liên quan**
- Cấu hình: `config.yaml`
- Script chính: `mini_soar.py`
- Phụ thuộc: `requirements.txt`

---



