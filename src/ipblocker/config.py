import os
from pathlib import Path

IPBLOCKER_HOME = Path(os.getenv("IPBLOCKER_HOME", Path.home() / ".config" / "ipblocker"))
RULE_DIR = IPBLOCKER_HOME / "rules"
OUTPUT_DIR = IPBLOCKER_HOME / "dist"
STAT_LOG_FILE = IPBLOCKER_HOME / "stats.log"

for path in (IPBLOCKER_HOME, OUTPUT_DIR, RULE_DIR):
    path.mkdir(parents=True, exist_ok=True)


NGINX_LOG_HOME = Path(os.getenv("IPBLOCKER_NGINX_LOG_HOME", "/var/log/nginx"))
WHITELIST_HOSTS = RULE_DIR / "whitelist_hosts.txt"
WHITELIST_IPS = RULE_DIR / "whitelist_ips.txt"
