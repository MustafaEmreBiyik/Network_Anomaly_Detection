import os
import platform
import sqlite3
import subprocess
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

WHITELIST = os.getenv("WHITELIST_IPS", "127.0.0.1,localhost,192.168.1.1,0.0.0.0").split(",")
BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", "3600"))

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "alerts.db")

_BLOCKED_IPS_DDL = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL
);
"""


def _get_fw_connection():
    conn = sqlite3.connect(_DB_PATH)
    conn.execute(_BLOCKED_IPS_DDL)
    return conn


def _record_block(ip_address: str):
    now = datetime.now(timezone.utc).isoformat()
    with _get_fw_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at) VALUES (?, ?)",
            (ip_address, now),
        )
        conn.commit()


def _remove_block_record(ip_address: str):
    with _get_fw_connection() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip_address,))
        conn.commit()

def get_os():
    return platform.system()


def list_blocked_ips():
    """Return firewall-managed blocked IP rules created by this app."""
    os_name = get_os()

    try:
        if os_name == "Windows":
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return []

            blocked_rules = []
            current_rule = {}
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                if line.startswith("Rule Name:"):
                    if current_rule.get("name", "").startswith("Block_AI_"):
                        remote_ip = current_rule.get("remote_ip")
                        if remote_ip and remote_ip not in ("Any", "LocalSubnet"):
                            blocked_rules.append({
                                "rule_name": current_rule["name"],
                                "ip": remote_ip,
                                "direction": current_rule.get("direction", "In"),
                            })
                    current_rule = {"name": line.split(":", 1)[1].strip()}
                elif ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if key == "remoteip":
                        current_rule["remote_ip"] = value
                    elif key == "direction":
                        current_rule["direction"] = value
                    elif key == "action":
                        current_rule["action"] = value

            if current_rule.get("name", "").startswith("Block_AI_"):
                remote_ip = current_rule.get("remote_ip")
                if remote_ip and remote_ip not in ("Any", "LocalSubnet"):
                    blocked_rules.append({
                        "rule_name": current_rule["name"],
                        "ip": remote_ip,
                        "direction": current_rule.get("direction", "In"),
                    })

            deduped = {}
            for rule in blocked_rules:
                deduped[rule["ip"]] = rule
            return sorted(deduped.values(), key=lambda item: item["ip"])

        if os_name == "Linux":
            result = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return []

            blocked_rules = []
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if "-s" in parts and "-j" in parts:
                    source_ip = parts[parts.index("-s") + 1]
                    target = parts[parts.index("-j") + 1]
                    if target == "DROP":
                        blocked_rules.append({
                            "rule_name": f"iptables_DROP_{source_ip}",
                            "ip": source_ip,
                            "direction": "In",
                        })
            return blocked_rules

    except Exception as exc:
        print(f"❌ Firewall list error: {exc}")

    return []

def block_ip(ip_address):
    """
    Verilen IP adresini işletim sistemi seviyesinde engeller.
    """
    if ip_address in WHITELIST:
        print(f"⚠️  UYARI: {ip_address} güvenli listede, engellenemez!")
        return False

    os_name = get_os()
    
    try:
        if os_name == "Windows":
            # Windows Firewall (Netsh)
            rule_name = f"Block_AI_{ip_address}"
            
            # Zaten var mı kontrol et
            check_cmd = f"netsh advfirewall firewall show rule name=\"{rule_name}\""
            if subprocess.call(check_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                return True # Zaten engelli

            command = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
            os.system(command)
            print(f"🚫 [WINDOWS] {ip_address} güvenlik duvarı tarafından engellendi!")

        elif os_name == "Linux":
            check_cmd = f"iptables -C INPUT -s {ip_address} -j DROP"
            if subprocess.call(check_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                _record_block(ip_address)
                return True

            command = f"iptables -A INPUT -s {ip_address} -j DROP"
            os.system(command)
            print(f"🚫 [LINUX] {ip_address} güvenlik duvarı tarafından engellendi!")

        _record_block(ip_address)
        return True

    except Exception as e:
        print(f"❌ Engelleme Hatası: {e}")
        return False


def unblock_ip(ip_address):
    """Remove firewall block rule for the given IP if it exists."""
    os_name = get_os()
    rule_name = f"Block_AI_{ip_address}"

    try:
        if os_name == "Windows":
            command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = os.system(command)
            if result == 0:
                _remove_block_record(ip_address)
                print(f"✅ [WINDOWS] {ip_address} engeli kaldırıldı.")
                return True
        elif os_name == "Linux":
            command = f"iptables -D INPUT -s {ip_address} -j DROP"
            result = os.system(command)
            if result == 0:
                _remove_block_record(ip_address)
                print(f"✅ [LINUX] {ip_address} engeli kaldırıldı.")
                return True

        _remove_block_record(ip_address)
        print(f"⚠️ {ip_address} için kaldırılacak bir kural bulunamadı.")
        return False
    except Exception as exc:
        print(f"❌ Engeli kaldırma hatası: {exc}")
        return False


def check_expired_blocks(ttl_seconds: int | None = None):
    """Unblock IPs whose block duration has exceeded the TTL."""
    if ttl_seconds is None:
        ttl_seconds = BLOCK_TTL_SECONDS

    now = datetime.now(timezone.utc)
    expired: list[str] = []

    try:
        with _get_fw_connection() as conn:
            rows = conn.execute("SELECT ip, blocked_at FROM blocked_ips").fetchall()
    except sqlite3.Error as exc:
        print(f"❌ TTL check DB error: {exc}")
        return expired

    for ip, blocked_at_str in rows:
        try:
            blocked_at = datetime.fromisoformat(blocked_at_str)
            if blocked_at.tzinfo is None:
                blocked_at = blocked_at.replace(tzinfo=timezone.utc)
            if (now - blocked_at).total_seconds() >= ttl_seconds:
                unblock_ip(ip)
                expired.append(ip)
                print(f"⏰ TTL expired — auto-unblocked {ip}")
        except (ValueError, TypeError):
            _remove_block_record(ip)

    return expired
