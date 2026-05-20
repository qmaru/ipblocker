import argparse
import datetime
import ipaddress
import itertools
import os
import re
import shutil
import subprocess
from pathlib import Path

import polars as pl

import ipblocker.config as config

NGINX_ACCESS_LOG = config.NGINX_LOG_HOME / "access.log"
BLOCKED_IPS_FILE = config.OUTPUT_DIR / "blocked_ips.txt"
NFT_OUTPUT_FILE = config.OUTPUT_DIR / "blocked_ips.nft"
NFT_BATCH_SIZE = 1000


class AutoBlockIP:
    def __init__(self) -> None:
        self.blocked_ips_file = BLOCKED_IPS_FILE
        self.nft_output_file = NFT_OUTPUT_FILE
        self.whitelist_ip_file = config.WHITELIST_IPS
        self.whitelist_host_file = config.WHITELIST_HOSTS

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
        self.whitelist_cidrs = self._read_whitelist_cidrs(self.whitelist_ip_file)
        self.whitelist_host_suffixes = self._read_whitelist_host_suffixes(self.whitelist_host_file)

    def _read_text_lines(self, file_path: Path) -> list[str]:
        values = []
        if file_path.exists():
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    value = line.strip()
                    if value and not value.startswith("#"):
                        values.append(value)
        return values

    def _read_whitelist_cidrs(self, file_path: Path) -> list:
        cidrs = []
        for cidr in self._read_text_lines(file_path):
            try:
                cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"忽略无效的 IP 白名单配置: {cidr}")
        return cidrs

    def _read_whitelist_host_suffixes(self, file_path: Path) -> tuple[str, ...]:
        suffixes = []
        for suffix in self._read_text_lines(file_path):
            normalized = suffix.lower().lstrip(".").rstrip(".")
            if normalized:
                suffixes.append(normalized)
        return tuple(sorted(set(suffixes)))

    def _is_ip_whitelisted(self, ip: str, whitelist_cidrs: list) -> bool:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in whitelist_cidrs)

    def _normalize_host(self, host: str) -> str:
        normalized = host.strip().lower().rstrip(".")
        if normalized.startswith("["):
            end = normalized.find("]")
            if end != -1:
                return normalized[1:end]

        if normalized.count(":") == 1:
            candidate, port = normalized.rsplit(":", 1)
            if port.isdigit():
                normalized = candidate

        return normalized

    def _is_host_whitelisted(self, host: str) -> bool:
        if not self.whitelist_host_suffixes:
            return False

        normalized_host = self._normalize_host(host)
        if not normalized_host:
            return False

        return any(
            normalized_host == suffix or normalized_host.endswith(f".{suffix}")
            for suffix in self.whitelist_host_suffixes
        )

    def _read_ips_txt(self, file_path: Path) -> set:
        ips = set()
        for ip in self._read_text_lines(file_path):
            ips.add(ip)
        return ips

    def _write_ips_txt(self, ips: set, file_path: Path):
        with file_path.open("w", encoding="utf-8") as f:
            for ip in sorted(ips):
                f.write(f"{ip}\n")

    def _iter_ip_batches(self, ipset: list[str], batch_size: int = NFT_BATCH_SIZE):
        iterator = iter(ipset)
        while batch := list(itertools.islice(iterator, batch_size)):
            yield batch

    def _build_nft_commands(self, action: str, ipset: list[str]) -> str:
        commands = []
        for batch in self._iter_ip_batches(ipset):
            ips = ", ".join(batch)
            commands.append(f"{action} element inet q_filter blocked_ips {{ {ips} }}")
        return "\n".join(commands) + ("\n" if commands else "")

    def _write_nft_file(self, ipset: list[str], output_file: Path):
        with output_file.open("w", encoding="utf-8") as f:
            if not ipset:
                f.write("# blocked_ips is empty\n")
                return

            f.write(self._build_nft_commands("add", ipset))

    def _run_nft_command(self, action: str, ipset: list[str]) -> bool:
        if not ipset:
            return True

        nft_commands = self._build_nft_commands(action, ipset)
        try:
            subprocess.run(
                ["nft", "-f", "-"],
                input=nft_commands,
                text=True,
                check=True,
            )
        except FileNotFoundError:
            print("nft command not found. Exiting.")
            return False
        except subprocess.CalledProcessError as exc:
            print(f"nft {action} element 执行失败，退出码: {exc.returncode}")
            return False

        return True

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

    def _parse_log_batch(self, log_path: Path, batch_size: int = 10000):
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
        if df.is_empty():
            return []

        host_whitelist_mask = pl.col("host").map_elements(
            self._is_host_whitelisted,
            return_dtype=pl.Boolean,
        )
        condition1 = pl.col("user_agent") == "-"
        condition2 = pl.col("status") == 444

        filtered_df = df.filter(~host_whitelist_mask & (condition1 | condition2))
        return filtered_df["ip"].unique().to_list()

    def _process_log_batch(self, logs: list[tuple[str, ...]]) -> list[str]:
        """处理单批日志，返回需要封禁的 IP"""
        df = self._build_dataframe(logs)
        ips = self._get_blocked_ips(df)
        return self._filter_whitelisted_ips(ips)

    def _log_recorder(self, total_count: int, new_count: int):
        """记录封禁统计日志"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with config.STAT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{now} -> 总数:{total_count} 新增:{new_count}\n")

    def _apply_nft_rules(self, ipset: list[str]) -> None:
        """应用 nft 规则"""
        print(f"应用新规则 {len(ipset)} IPs...")
        self._run_nft_command("add", ipset)

    def run_block_core(self, dry_run: bool = False):
        """核心封禁逻辑"""
        if not os.path.exists(NGINX_ACCESS_LOG):
            print(f"日志文件 {NGINX_ACCESS_LOG} 不存在，退出。")
            return

        # 读取现有的封禁 IP
        before_set = self._read_ips_txt(self.blocked_ips_file)

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

            self._write_ips_txt(all_ips, self.blocked_ips_file)
            self._write_nft_file(list(all_ips), self.nft_output_file)

            if not dry_run:
                self._apply_nft_rules(new_ips)
                self._log_recorder(after_count, new_count)
            print(f"Blocked IPs: {after_count}, New: {new_count}")
        else:
            print("没有新的 IP 需要封禁")

    def run_generate_nft_from_txt(self):
        """根据已保存的 IP 列表重新生成 NFT 规则文件"""
        ips = self._read_ips_txt(self.blocked_ips_file)
        if ips:
            self._write_nft_file(list(ips), self.nft_output_file)
            print(f"已根据 {self.blocked_ips_file} 重新生成 {self.nft_output_file}")
        else:
            print(f"{self.blocked_ips_file} 文件为空，未生成 NFT 规则文件。")

    def run_purge_whitelisted_ips(self):
        """从已保存的 IP 列表中清除白名单 IP"""

        if not os.path.exists(self.blocked_ips_file):
            print(f"{self.blocked_ips_file} 不存在，无需处理。")
            return

        # 读取现有的封禁 IP
        blocked_ips = self._read_ips_txt(self.blocked_ips_file)
        original_count = len(blocked_ips)

        # 过滤掉白名单中的 IP
        filtered_ips = set(self._filter_whitelisted_ips(list(blocked_ips)))

        # 保存清理后的 IP 列表
        self._write_ips_txt(filtered_ips, self.blocked_ips_file)
        self._write_nft_file(list(filtered_ips), self.nft_output_file)

        removed_count = original_count - len(filtered_ips)
        print(f"已清除白名单 IP: {removed_count} 个，剩余 IP: {len(filtered_ips)} 个")

    def run_remove_ips(self, ips: list[str], apply_nft: bool = True):
        """从封禁列表中移除指定 IP，并加入白名单"""
        # 验证 IP 格式
        valid_ips = []
        invalid_ips = []
        for ip in ips:
            ip = ip.strip()
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                invalid_ips.append(ip)

        if invalid_ips:
            print(f"以下 IP 格式无效，已忽略: {', '.join(invalid_ips)}")

        if not valid_ips:
            print("没有有效的 IP，退出。")
            return

        # 读取当前封禁列表
        blocked = self._read_ips_txt(self.blocked_ips_file)

        # 要从封禁列表中移除的 IP（仅限当前已被封禁的）
        to_remove = [ip for ip in valid_ips if ip in blocked]
        not_blocked = [ip for ip in valid_ips if ip not in blocked]

        # 更新封禁文件和 nft 输出文件
        new_blocked = blocked - set(to_remove)
        self._write_ips_txt(new_blocked, self.blocked_ips_file)
        self._write_nft_file(list(new_blocked), self.nft_output_file)

        # 将 IP 添加到白名单文件（如果尚不存在）
        existing_whitelist = set(self._read_text_lines(self.whitelist_ip_file))

        to_add_whitelist = [ip for ip in valid_ips if ip not in existing_whitelist]
        if to_add_whitelist:
            with self.whitelist_ip_file.open("a", encoding="utf-8") as f:
                for ip in to_add_whitelist:
                    f.write(f"{ip}\n")
            # 刷新内存中的白名单
            self.whitelist_cidrs = self._read_whitelist_cidrs(self.whitelist_ip_file)

        # 立即在 nft 中删除这些元素
        if to_remove and apply_nft:
            print(f"从 nft 集合中移除: {', '.join(to_remove)}")
            self._run_nft_command("delete", to_remove)

        print(
            f"已从封禁列表移除: {len(to_remove)} 个。未在封禁列表中的 IP: {', '.join(not_blocked) if not_blocked else '无'}"
        )


def make_parser():
    env_vars = ["IPBLOCKER_HOME", "IPBLOCKER_NGINX_LOG_HOME"]
    env_lines = "\n".join(f"- {var}" for var in env_vars)

    desc = f"自动封禁恶意IP工具\n\n环境变量:\n{env_lines}"

    parser = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawTextHelpFormatter
    )

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

    parser.add_argument(
        "--remove",
        type=str,
        help="从封禁列表移除 IP，多个用逗号分隔，例如: 1.2.3.4,2.2.2.2",
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
        if not shutil.which("nft"):
            print("nft command not found. Exiting.")
            return

        print(">> 正式执行，读取日志并应用规则")
        auto_blocker.run_block_core(dry_run=False)
    elif args.remove:
        # args.remove 是以逗号分隔的字符串
        print(">> 从封禁列表移除指定 IP，并加入白名单")
        raw = args.remove
        # 支持逗号或空格分隔
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        auto_blocker.run_remove_ips(parts, apply_nft=True)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
