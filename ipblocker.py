import argparse
import datetime
import ipaddress
import os
import re
import shutil
from pathlib import Path

import polars as pl

NGINX_DEFAULT_LOG = "/var/log/nginx/access.log"
NGINX_ACCESS_LOG: str = NGINX_DEFAULT_LOG if os.path.exists(NGINX_DEFAULT_LOG) else "access.log"

SAFE_HOSTS = [
    "api.373.moe",
    "bot.373.moe",
    "cloud.hm773.net",
    "grpc.hm773.net",
    "mirror.373.moe",
    "tools.373.moe",
    "v.373.moe",
    "api.toho373.com",
    "book.toho373.com",
    "code.toho373.com",
    "iptv.toho373.com",
    "menu.toho373.com",
    "www.toho373.com",
]


class AutoBlockIP:
    def __init__(self) -> None:
        self.WORK_DIR = Path(os.path.abspath(os.path.dirname(__file__)))
        self.OUTPUT_DIR = self.WORK_DIR / "outputs"

        self.WHITELIST_FILE = self.WORK_DIR / "whitelist_ips.txt"
        self.STATS_LOG_FILE = self.WORK_DIR / "stats.log"

        self.IPS_TXT_FILE = self.OUTPUT_DIR / "blocked_ips.txt"
        self.NFT_OUTPUT_FILE = self.OUTPUT_DIR / "blocked_ips.nft"

        self.LOG_PATTERN = (
            r"(\d+\.\d+\.\d+\.\d+)"
            r" - (.*?) "
            r"\[(.*?)\] "
            r'"(.*?)" '
            r'"(.*?)" '
            r"(\d+) "
            r"(\d+) "
            r'"(.*?)" '
            r'"(.*?)" '
            r'"(.*?)" '
            r'"(.*?)"'
        )

        self.init()

    def init(self):
        if not os.path.exists(self.OUTPUT_DIR):
            os.makedirs(self.OUTPUT_DIR)

        self.whitelist_cidrs = self._read_whitelist_cidrs(self.WHITELIST_FILE)

    def _read_whitelist_cidrs(self, file_path: Path) -> list:
        cidrs = []
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                for line in f:
                    cidr = line.strip()
                    if cidr:
                        cidrs.append(ipaddress.ip_network(cidr))
        return cidrs

    def _is_ip_whitelisted(self, ip: str, whitelist_cidrs: list) -> bool:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in whitelist_cidrs)

    def _read_ips_txt(self, file_path: Path) -> set:
        ips = set()
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        ips.add(ip)
        return ips

    def _write_ips_txt(self, ips: set, file_path: Path):
        with open(file_path, "w", encoding="utf-8") as f:
            for ip in sorted(ips):
                f.write(f"{ip}\n")

    def _write_nft_file(self, ipset: list[str], output_file: Path):
        ips = ", ".join(ipset)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"add element inet q_filter blocked_ips {{ {ips} }}\n")

    def _filter_whitelisted_ips(self, ips: list[str]) -> list[str]:
        """过滤白名单 IP"""
        if not self.whitelist_cidrs:
            return ips
        return [ip for ip in ips if not self._is_ip_whitelisted(ip, self.whitelist_cidrs)]

    def _build_dataframe(self, logs: list[tuple[str, ...]]) -> pl.DataFrame:
        """将日志列表转换为 Polars DataFrame"""
        columns = [
            "ip",
            "remote_user",
            "time",
            "request",
            "host",
            "status",
            "size",
            "referrer",
            "request_time",
            "user_agent",
            "x_forwarded_for",
        ]

        df = pl.DataFrame(logs, schema=columns, orient="row")
        df = df.with_columns(
            [
                pl.col("time").str.to_datetime(format="%d/%b/%Y:%H:%M:%S %z"),
                pl.col("status").cast(pl.Int64),
                pl.col("size").cast(pl.Int64),
                pl.col("request_time").cast(pl.Float64),
            ]
        )

        return df

    def _parse_log_batch(self, log_path: str, batch_size: int = 10000):
        """逐批解析日志文件"""
        batch = []
        with open(log_path, "r") as f:
            for line in f:
                m = re.match(self.LOG_PATTERN, line)
                if m:
                    batch.append(m.groups())
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
            if batch:
                yield batch

    def _get_blocked_ips(self, df: pl.DataFrame) -> list[str]:
        """从 dataFrame 中提取需要封禁的 IP"""
        condition1 = pl.col("user_agent") == "-"
        condition2 = (pl.col("status") == 444) & (~pl.col("host").is_in(SAFE_HOSTS))

        filtered_df = df.filter(condition1 | condition2)
        return filtered_df["ip"].unique().to_list()

    def _process_log_batch(self, logs: list[tuple[str, ...]]) -> list[str]:
        """处理单批日志，返回需要封禁的 IP"""
        df = self._build_dataframe(logs)
        ips = self._get_blocked_ips(df)
        return self._filter_whitelisted_ips(ips)

    def _log_recorder(self, total_count: int, new_count: int):
        """记录封禁统计日志"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.STATS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{now} -> 总数:{total_count} 新增:{new_count}\n")

    def _apply_nft_rules(self, ipset: list[str]) -> None:
        """应用 nft 规则"""
        ips: str = ", ".join(ipset)
        print(f"应用新规则 {len(ipset)} IPs...")
        os.system(f"nft add element inet q_filter blocked_ips {{ {ips} }}")

    def run_block_core(self, dry_run: bool = False):
        """核心封禁逻辑"""
        if not os.path.exists(NGINX_ACCESS_LOG):
            print(f"日志文件 {NGINX_ACCESS_LOG} 不存在，退出。")
            return

        # 读取现有的封禁 IP
        before_set = self._read_ips_txt(self.IPS_TXT_FILE)

        all_ips = set()
        # 逐批处理日志文件
        for logs_batch in self._parse_log_batch(NGINX_ACCESS_LOG):
            blocked_ips = self._process_log_batch(logs_batch)
            all_ips.update(blocked_ips)

        # 收集所有需要封禁的 IP
        all_ips.update(before_set)

        new_ips = sorted(list(all_ips - before_set))
        if new_ips:
            after_count = len(all_ips)
            new_count = len(new_ips)

            self._write_ips_txt(all_ips, self.IPS_TXT_FILE)
            self._write_nft_file(list(all_ips), self.NFT_OUTPUT_FILE)

            if not dry_run:
                self._apply_nft_rules(new_ips)
                self._log_recorder(after_count, new_count)
            print(f"Blocked IPs: {after_count}, New: {new_count}")
        else:
            print("没有新的 IP 需要封禁")

    def run_generate_nft_from_txt(self):
        """根据已保存的 IP 列表重新生成 NFT 规则文件"""
        ips = self._read_ips_txt(self.IPS_TXT_FILE)
        if ips:
            self._write_nft_file(list(ips), self.NFT_OUTPUT_FILE)
            print(f"已根据 {self.IPS_TXT_FILE} 重新生成 {self.NFT_OUTPUT_FILE}")
        else:
            print(f"{self.IPS_TXT_FILE} 文件为空，未生成 NFT 规则文件。")

    def run_purge_whitelisted_ips(self):
        """从已保存的 IP 列表中清除白名单 IP"""

        if not os.path.exists(self.IPS_TXT_FILE):
            print(f"{self.IPS_TXT_FILE} 不存在，无需处理。")
            return

        # 读取现有的封禁 IP
        blocked_ips = self._read_ips_txt(self.IPS_TXT_FILE)
        original_count = len(blocked_ips)

        # 过滤掉白名单中的 IP
        filtered_ips = set(self._filter_whitelisted_ips(list(blocked_ips)))

        # 保存清理后的 IP 列表
        self._write_ips_txt(filtered_ips, self.IPS_TXT_FILE)
        self._write_nft_file(list(filtered_ips), self.NFT_OUTPUT_FILE)

        removed_count = original_count - len(filtered_ips)
        print(f"已清除白名单 IP: {removed_count} 个，剩余 IP: {len(filtered_ips)} 个")


def make_parser():
    parser = argparse.ArgumentParser(description="自动封禁恶意IP工具")

    parser.add_argument(
        "--purge",
        action="store_true",
        help="刷新 IP 文件",
    )

    parser.add_argument(
        "--generate",
        action="store_true",
        help="重新生成 NFT 规则文件",
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="调试",
    )

    parser.add_argument(
        "--start",
        action="store_true",
        help="正式执行",
    )

    return parser


def main():
    parser = make_parser()
    args = parser.parse_args()

    auto_blocker = AutoBlockIP()

    if args.purge:
        print(">> 执行清理白名单 IP 操作")
        auto_blocker.run_purge_whitelisted_ips()
        return
    elif args.generate:
        print(">> 重新生成 NFT 规则文件")
        auto_blocker.run_generate_nft_from_txt()
    elif args.test:
        print(">> 测试运行，读取日志但不应用规则")
        auto_blocker.run_block_core(dry_run=True)
    elif args.start:
        if not shutil.which("/usr/sbin/nft"):
            print("nft command not found. Exiting.")
            return

        print(">> 正式执行，读取日志并应用规则")
        auto_blocker.run_block_core(dry_run=False)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
