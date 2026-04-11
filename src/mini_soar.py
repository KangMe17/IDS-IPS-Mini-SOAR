#!/usr/bin/env python3
"""
mini_soar.py
--------------------------------------------------------------------------------
A lightweight, single-file SOAR engine for Suricata.
Features:
  - Log Tailing (Eve JSON) with rotation support.
  - Threat Response (NFTables/IPTables blocking, isolation).
  - Alerting (Telegram, Email).
  - Persistence (SQLite).

Usage:
    python3 mini_soar.py --config config.yaml
--------------------------------------------------------------------------------
"""

import argparse
import json
import logging
import os
import shlex
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs

# ==============================================================================
# 1. IMPORTS & DEPENDENCY HANDLING
# ==============================================================================
try:
    import ipaddress
    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ==============================================================================
# 2. CONFIGURATION & CONSTANTS
# ==============================================================================
DEFAULT_CONFIG = {
    "eve_log": "/var/log/suricata/eve.json",
    "db_path": "/var/lib/mini_soar/mini_soar.db",
    "use_nft": True,
    "ban_ttl": 3600,
    "unban_check_interval": 30,
    "http_api_port": 9000,
    "dry_run": False,
    "whitelist": ["127.0.0.1", "192.168.1.0/24"],
    "ignore_keywords": ["SURICATA STREAM", "SURICATA TCP", "GPL ICMP", "ICMP PING"],
    "rules": [
        {
            "name": "SQL Injection",
            "keywords": ["SQL Error", "UNION SELECT", "SQL Injection"],
            "action": "block_ip",
            "ttl": 3600,
            "quarantine": True,
            "block_domain": True
        },
        {
            "name": "XSS / Scripting",
            "keywords": ["Cross Site Scripting", "<script>", "XSS"],
            "action": "block_ip",
            "ttl": 3600
        },
        {
            "name": "RCE / Command Injection",
            "keywords": ["Command Injection", "Shellshock", "bash -c", "wget", "curl"],
            "action": "block_ip",
            "ttl": 7200
        },
        {
            "name": "Scanning Activities",
            "keywords": ["ET SCAN", "NMAP", "Masscan", "ZMap"],
            "action": "block_ip",
            "ttl": 600
        },
        {
            "name": "Malware / C2",
            "keywords": ["C2", "Command and Control", "Beacon", "Malware"],
            "action": "block_ip",
            "ttl": 86400,
            "quarantine_dst": True
        }
    ]
}

logger = logging.getLogger("mini_soar")

def setup_logging(log_file: str = '/var/log/mini_soar.log', debug: bool = False):
    """Cấu hình logging ra cả File và Console."""
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')

    # File Handler
    try:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except PermissionError:
        print(f"Warning: Cannot write to {log_file}. Logging to console only.")

    # Console Handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# ==============================================================================
# 3. UTILITIES
# ==============================================================================
def valid_ip(ip: str) -> bool:
    """Kiểm tra tính hợp lệ của IP."""
    if not ip:
        return False
    if HAS_IPADDRESS:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    return len(ip) > 6 and "." in ip  # Fallback đơn giản


# ==============================================================================
# 4. DATABASE LAYER
# ==============================================================================
class DatabaseManager:
    """Quản lý kết nối và truy vấn SQLite."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._ensure_directory()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")  # Tăng tốc độ ghi
        self.lock = threading.Lock()
        self._init_tables()

    def _ensure_directory(self):
        db_dir = os.path.dirname(self.path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"Created DB directory: {db_dir}")
            except OSError as e:
                logger.error(f"Cannot create DB dir {db_dir}: {e}. Fallback to /tmp")
                self.path = "/tmp/mini_soar.db"

    def _init_tables(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    event JSON,
                    severity TEXT,
                    handled INTEGER DEFAULT 0
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    action_type TEXT,
                    target TEXT,
                    params JSON,
                    added_at TEXT
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS bans (
                    ip TEXT PRIMARY KEY,
                    added_at TEXT,
                    expires_at TEXT,
                    reason TEXT
                )""")
            self.conn.commit()

    def add_incident(self, src_ip: str, event: Dict, severity: str = "medium") -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO incidents(timestamp, src_ip, event, severity) VALUES (?, ?, ?, ?)",
                (now, src_ip, json.dumps(event), severity)
            )
            self.conn.commit()
            return cur.lastrowid

    def mark_handled(self, incident_id: int):
        with self.lock:
            self.conn.execute("UPDATE incidents SET handled = 1 WHERE id = ?", (incident_id,))
            self.conn.commit()

    def log_action(self, incident_id: int, action_type: str, target: str, params: Dict):
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.conn.execute(
                "INSERT INTO actions(incident_id, action_type, target, params, added_at) VALUES (?, ?, ?, ?, ?)",
                (incident_id, action_type, target, json.dumps(params), now)
            )
            self.conn.commit()

    def add_ban(self, ip: str, ttl: int, reason: str):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl) if ttl else None
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO bans(ip, added_at, expires_at, reason) VALUES (?, ?, ?, ?)",
                (ip, now.isoformat(), expires.isoformat() if expires else None, reason)
            )
            self.conn.commit()

    def remove_ban(self, ip: str):
        with self.lock:
            self.conn.execute("DELETE FROM bans WHERE ip = ?", (ip,))
            self.conn.commit()

    def get_expired_bans(self) -> List[str]:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.execute(
                "SELECT ip FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,)
            )
            return [row[0] for row in cur.fetchall()]

    def get_active_bans(self) -> List[Tuple[str, str]]:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.execute(
                "SELECT ip, expires_at FROM bans WHERE expires_at > ? OR expires_at IS NULL", (now,)
            )
            return cur.fetchall()


# ==============================================================================
# 5. FIREWALL DRIVER (NFTABLES & IPTABLES)
# ==============================================================================
class FirewallDriver:
    """Xử lý các lệnh tương tác với hệ thống Firewall (NFT hoặc IPtables)."""

    def __init__(self, use_nft: bool = True, dry_run: bool = False):
        self.use_nft = use_nft
        self.dry_run = dry_run
        
        if self.use_nft and self.check_nft_installed():
            self._init_nft_structure()
        else:
            self.use_nft = False # Fallback to iptables if nft missing

    def _run_cmd(self, cmd: str) -> bool:
        if self.dry_run:
            logger.info(f"[DRY_RUN] Exec: {cmd}")
            return True
        try:
            #logger.debug(f"Exec: {cmd}")
            subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {cmd} | Exit: {e.returncode}")
            return False

    # --- NFTABLES METHODS ---
    def check_nft_installed(self) -> bool:
        return subprocess.call(["which", "nft"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

    def _init_nft_structure(self):
        # PHẦN 1: CẤU HÌNH IPS & BLOCKING (Sửa lại cho chuẩn Gateway)
        # ======================================================================
        # 1. Tạo bảng và set 'blocked' (dùng cho tính năng Ban IP 1 giờ)
        self._run_cmd("nft add table inet filter")
        self._run_cmd("nft 'add set inet filter blocked { type ipv4_addr; flags timeout; }'")
        
        # 2. Tạo Chain INPUT và FORWARD
        self._run_cmd("nft 'add chain inet filter input { type filter hook input priority 0; }'")
        self._run_cmd("nft 'add chain inet filter forward { type filter hook forward priority 0; }'")
        
        # 3. THIẾT LẬP LUẬT (Flush để làm sạch trước khi add)
        self._run_cmd("nft flush chain inet filter input")
        self._run_cmd("nft flush chain inet filter forward")

        # --- Rule cho INPUT (Bảo vệ chính máy Suricata) ---
        self._run_cmd("nft add rule inet filter input ip saddr @blocked drop")

        # --- Rule cho FORWARD (Bảo vệ máy DVWA phía sau - QUAN TRỌNG) ---
        # Ưu tiên 1: Chặn IP xấu ngay lập tức
        self._run_cmd("nft add rule inet filter forward ip saddr @blocked drop")
        
        # Ưu tiên 2: Chuyển traffic sạch còn lại vào NFQUEUE số 0 cho Suricata soi
        # 'bypass': Giúp mạng không bị đứt nếu lỡ Suricata bị tắt
        self._run_cmd("nft add rule inet filter forward queue num 0 bypass")


        # ======================================================================
        # PHẦN 2: CẤU HÌNH QUARANTINE (Giữ nguyên code cũ của bạn)
        # ======================================================================
        # Structure for Quarantine (MiniSOAR Custom Table)
        self._run_cmd("nft add table inet minisoar")
        self._run_cmd("nft 'add set inet minisoar quarantine_ips { type ipv4_addr; }'")
        
        # Chains for Input/Forward/Output
        for chain, hook in [("input_chain", "input"), ("forward_chain", "forward"), ("output_chain", "output")]:
            # Lưu ý: Priority của quarantine nên để thấp hơn hoặc bằng filter
            self._run_cmd(f"nft 'add chain inet minisoar {chain} {{ type filter hook {hook} priority 0; }}'")
            self._run_cmd(f"nft flush chain inet minisoar {chain}")
          
        # Chains for Input/Forward/Output
        for chain, hook in [("input_chain", "input"), ("forward_chain", "forward"), ("output_chain", "output")]:
            self._run_cmd(f"nft 'add chain inet minisoar {chain} {{ type filter hook {hook} priority 0; }}'")
            self._run_cmd(f"nft flush chain inet minisoar {chain}")
            # Block traffic related to quarantine_ips
            if chain == "output_chain":
                self._run_cmd(f"nft add rule inet minisoar {chain} ip daddr @quarantine_ips drop")
            else:
                self._run_cmd(f"nft add rule inet minisoar {chain} ip saddr @quarantine_ips drop")

    def block_ip(self, ip: str, ttl: int) -> bool:
        """Chặn IP. Tự động chọn NFT hoặc Iptables."""
        if not valid_ip(ip):
            logger.warning(f"Invalid IP to block: {ip}")
            return False

        if self.use_nft:
            # NFTables with timeout
            safe_ip = shlex.quote(ip)
            cmd = f"nft add element inet filter blocked {{ {safe_ip} timeout {ttl}s }}"
            return self._run_cmd(cmd)
        else:
            # IPtables Fallback
            return self._iptables_block(ip)

    def unblock_ip(self, ip: str) -> bool:
        if self.use_nft:
            safe_ip = shlex.quote(ip)
            # NFT doesn't throw error if element missing usually, but we try/catch in _run_cmd
            # Note: Explicitly deleting element
            return self._run_cmd(f"nft delete element inet filter blocked {{ {safe_ip} }}")
        else:
            return self._iptables_unblock(ip)

    def quarantine_host(self, ip: str) -> bool:
        if not self.use_nft:
            logger.warning("Quarantine only supported with NFTables currently.")
            return False
        safe_ip = shlex.quote(ip)
        return self._run_cmd(f"nft add element inet minisoar quarantine_ips {{ {safe_ip} }}")

    def remove_quarantine(self, ip: str) -> bool:
        if not self.use_nft: return False
        safe_ip = shlex.quote(ip)
        return self._run_cmd(f"nft delete element inet minisoar quarantine_ips {{ {safe_ip} }}")

    # --- IPTABLES HELPERS ---
    def _iptables_block(self, ip: str) -> bool:
        # Create chain if needed
        subprocess.run(["iptables", "-N", "MINISOAR_BLOCK"], stderr=subprocess.DEVNULL, check=False)
        # Ensure jump
        if subprocess.call(["iptables", "-C", "INPUT", "-j", "MINISOAR_BLOCK"], stderr=subprocess.DEVNULL) != 0:
             subprocess.run(["iptables", "-I", "INPUT", "-j", "MINISOAR_BLOCK"], check=False)
        
        # Add rule if not exists
        if subprocess.call(["iptables", "-C", "MINISOAR_BLOCK", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL) != 0:
            if self.dry_run:
                logger.info(f"[DRY_RUN] iptables block {ip}")
                return True
            subprocess.run(["iptables", "-I", "MINISOAR_BLOCK", "-s", ip, "-j", "DROP"], check=False)
        return True

    def _iptables_unblock(self, ip: str) -> bool:
        if self.dry_run:
            logger.info(f"[DRY_RUN] iptables unblock {ip}")
            return True
        subprocess.run(["iptables", "-D", "MINISOAR_BLOCK", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
        return True


# ==============================================================================
# 6. NOTIFICATION SYSTEM
# ==============================================================================
class Notifier:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.dry_run = config.get("dry_run", False)
        
        self.email_conf = config.get("email", {})
        self.tg_conf = config.get("telegram", {})

    def send(self, message: str, subject: str = "Mini-SOAR Alert"):
        logger.info(f"ALERT: {message}")
        if self.dry_run: return

        self._send_telegram(message)
        self._send_email(message, subject)

    def _send_telegram(self, message: str):
        if not HAS_REQUESTS or not self.tg_conf.get("enabled"):
            return
        
        token = self.tg_conf.get("token")
        chat_id = self.tg_conf.get("chat_id")
        if not token or not chat_id: return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            requests.post(url, json={
                "chat_id": chat_id,
                "text": f"[Mini-SOAR] {message}",
                "parse_mode": "Markdown"
            }, timeout=5)
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")

    def _send_email(self, message: str, subject: str):
        if not self.email_conf.get("smtp_server"): return
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg["From"] = self.email_conf.get("smtp_user")
            msg["To"] = self.email_conf.get("mail_to")
            msg["Subject"] = subject
            msg.attach(MIMEText(message, "plain"))

            server = smtplib.SMTP(self.email_conf["smtp_server"], self.email_conf.get("smtp_port", 587))
            server.starttls()
            server.login(self.email_conf["smtp_user"], self.email_conf["smtp_password"])
            server.sendmail(self.email_conf["smtp_user"], self.email_conf["mail_to"], msg.as_string())
            server.quit()
            logger.info(f"EMAIL SENT to {self.email_conf['mail_to']}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")


# ==============================================================================
# 7. CORE ENGINE
# ==============================================================================
class MiniSOAREngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db = DatabaseManager(config.get("db_path"))
        self.fw = FirewallDriver(use_nft=config.get("use_nft", True), dry_run=config.get("dry_run", False))
        self.notifier = Notifier(config)
        
        self.whitelist = config.get("whitelist", [])
        self.ban_ttl = config.get("ban_ttl", 3600)
        self.dedup_cache = {}  # Cache để chống spam alert: {(src, sig): timestamp}

        self._start_workers()

    def _start_workers(self):
        # 1. Restore bans from DB
        self._restore_active_bans()
        # 2. Start Unban thread
        t = threading.Thread(target=self._unban_worker, daemon=True)
        t.start()

    def _restore_active_bans(self):
        logger.info("Restoring active bans from DB...")
        count = 0
        for ip, expires_at_str in self.db.get_active_bans():
            if not expires_at_str: continue
            
            expires_at = datetime.fromisoformat(expires_at_str)
            remaining = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            
            if remaining > 0:
                if self.fw.block_ip(ip, remaining):
                    count += 1
        logger.info(f"Restored {count} IPs.")

    def _unban_worker(self):
        """Tiến trình chạy ngầm để mở khóa IP đã hết hạn."""
        interval = self.config.get("unban_check_interval", 30)
        while True:
            try:
                for ip in self.db.get_expired_bans():
                    logger.info(f"Auto-unban expired IP: {ip}")
                    self.fw.unblock_ip(ip)
                    self.db.remove_ban(ip)
            except Exception as e:
                logger.error(f"Unban worker error: {e}")
            time.sleep(interval)

    def is_whitelisted(self, ip_str: str) -> bool:
        """Kiểm tra IP whitelist (hỗ trợ CIDR)."""
        if not ip_str: return False
        
        # Check đơn giản string
        if ip_str in self.whitelist: return True
        
        if not HAS_IPADDRESS: return False

        try:
            target = ipaddress.ip_address(ip_str)
            for item in self.whitelist:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    if target in net: return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def process_event(self, event: Dict[str, Any]):
        """Hàm xử lý chính cho từng sự kiện log."""
        if event.get("event_type") != "alert": return

        alert = event.get("alert", {})
        src = event.get("src_ip")
        sig = alert.get("signature", "Unknown")
        
        # 1. Validation & Filtering
        if not src or self.is_whitelisted(src): return
        
        ignore_list = self.config.get("ignore_keywords", [])
        if any(kwd in sig for kwd in ignore_list): return

        # 2. Deduplication (60s cooldown per sig/ip)
        key = (src, sig)
        if key in self.dedup_cache:
            if time.time() - self.dedup_cache[key] < 60: return
        self.dedup_cache[key] = time.time()
        if len(self.dedup_cache) > 5000: self.dedup_cache.clear()

        # 3. Incident Creation
        logger.info(f"Incident: {src} | {sig}")
        incident_id = self.db.add_incident(src, event, str(alert.get("severity")))

        # 4. Rule Matching
        self._apply_rules(incident_id, src, sig, event)
        self.db.mark_handled(incident_id)

    def _apply_rules(self, incident_id: int, src: str, sig: str, event: Dict):
        matched = False
        for rule in self.config.get("rules", []):
            if any(kwd in sig for kwd in rule.get("keywords", [])):                
                # Action: Block IP
                if rule.get("action") == "block_ip":
                    ttl = rule.get("ttl", self.ban_ttl)
                    if self.fw.block_ip(src, ttl):
                        self.db.log_action(incident_id, "block_ip", src, {"ttl": ttl})
                        self.db.add_ban(src, ttl, sig)
                        self.notifier.send(f"Blocked {src} for {ttl}s (Rule: {rule['name']})")

                # Action: Quarantine
                if rule.get("quarantine"):
                    self.fw.quarantine_host(src)
                    self.db.log_action(incident_id, "quarantine", src, {})

                matched = True
                break
        
        if not matched:
            self.notifier.send(f"Unmatched Alert from {src}: {sig}")

    # --- API Action ---
    def manual_unban(self, ip: str):
        if self.fw.unblock_ip(ip):
            self.db.remove_ban(ip)
            return True
        return False


# ==============================================================================
# 8. INPUT HANDLERS (LOG TAILER & API)
# ==============================================================================
def tail_eve_log(filepath: str, callback):
    """Đọc log file liên tục (tương tự tail -f) hỗ trợ log rotation."""
    if not os.path.exists(filepath):
        logger.error(f"Log file not found: {filepath}")
        return

    f = open(filepath, 'r')
    f.seek(0, os.SEEK_END)
    cur_ino = os.fstat(f.fileno()).st_ino

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            # Check rotation
            try:
                if os.stat(filepath).st_ino != cur_ino:
                    logger.info(f"Log rotation detected on {filepath}")
                    f.close()
                    f = open(filepath, 'r')
                    cur_ino = os.fstat(f.fileno()).st_ino
            except Exception:
                pass
            continue

        try:
            callback(json.loads(line))
        except json.JSONDecodeError:
            pass


class APIHandler(BaseHTTPRequestHandler):
    engine = None  # Static reference

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/unban":
            query = parse_qs(parsed.query)
            ips = query.get('ip', [])
            if ips and self.engine:
                ip = ips[0]
                self.engine.manual_unban(ip)
                self.send_response(200)
                self.wfile.write(f"Unbanned {ip}".encode())
                return
            
            self.send_response(400)
            self.wfile.write(b"Missing 'ip' param")
        else:
            self.send_response(404)


# ==============================================================================
# 9. MAIN ENTRY POINT
# ==============================================================================
def load_config(path: Optional[str]) -> Dict:
    cfg = DEFAULT_CONFIG.copy()
    if path and HAS_YAML:
        try:
            with open(path) as f:
                update = yaml.safe_load(f)
                if update: cfg.update(update)
            logger.info(f"Loaded config from {path}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    elif path and not HAS_YAML:
        logger.warning("YAML module not installed. Using defaults.")
    return cfg

def main():
    parser = argparse.ArgumentParser(description="Mini-SOAR Engine")
    parser.add_argument('--config', '-c', help='Path to config.yaml')
    parser.add_argument('--dry-run', action='store_true', help='Test mode (no blocking)')
    args = parser.parse_args()

    # 1. Setup
    setup_logging(debug=True)
    cfg = load_config(args.config)
    if args.dry_run:
        cfg['dry_run'] = True

    logger.info("Starting Mini-SOAR Engine...")
    engine = MiniSOAREngine(cfg)

    # 2. Start API Server
    port = cfg.get('http_api_port', 9000)
    APIHandler.engine = engine
    api_thread = threading.Thread(
        target=HTTPServer(('0.0.0.0', port), APIHandler).serve_forever, 
        daemon=True
    )
    api_thread.start()
    logger.info(f"API Listening on port {port}")

    # 3. Start Log Tailing
    try:
        tail_eve_log(cfg.get('eve_log'), engine.process_event)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.critical(f"Fatal Error: {e}")

if __name__ == '__main__':
    main()
