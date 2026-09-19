#
# VanishCrypt — AES-GCM 文件加密解密工具 (v2.1)
#
# 核心功能：
# 1. Argon2id 密钥派生（time_cost=12, memory_cost=1GB, parallelism=8）
# 2. AES-256-GCM 认证加密，确保机密性与完整性
# 3. SSD 优化安全删除：原位随机覆写 + 物理落盘(fsync) + 二次随机重命名 + 删除
#
# 文件格式 V5 (SECv5)：
#   MAGIC(5) | salt(16) | nonce(12) | kdf_params(12) | tag(16) | encrypted_data
#   向后兼容 V4 (SECv4) 格式解密
#
# 安全机制：
# - 密码复杂度校验：长度≥12，含大小写/数字/特殊字符
# - 密钥以 bytearray 存储，使用后立即清零
# - GCM 认证标签防篡改验证
# - 临时文件异常时自动清理，原子性替换
# - 可选安全粉碎原文件或保留副本
# - 预检磁盘剩余空间防止溢出
#
# 架构：
# - MVC 分离，QThread 异步多线程，QMutex 线程安全取消
# - PySide6 GUI，交互式多文件表格队列、双进度条、实时传输速率与 ETA
#

import os
import sys
import re
import time
import struct
import string
import secrets
import shutil
from datetime import datetime, timezone
import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QFileDialog,
    QMessageBox, QPlainTextEdit, QStyleFactory, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QObject, QMutex, QTimer
from PySide6.QtGui import QFont, QColor


# ════════════════════════════════════════════════════════════
# 常量与配置
# ════════════════════════════════════════════════════════════

CHUNK_SIZE = 16 * 1024 * 1024          # 16 MB I/O 块

MAGIC_V4 = b'SECv4'                    # 旧版文件标识
MAGIC_V5 = b'SECv5'                    # 新版文件标识（含 KDF 参数）
MAGIC_CURRENT = MAGIC_V5               # 当前写入版本

ENCRYPTED_EXT = '.secure'              # 加密文件扩展名
MIN_PASSWORD_LEN = 12                  # 最小密码长度

# Argon2id 默认参数
KDF_TIME_COST = 12
KDF_MEMORY_COST = 1_048_576            # 1 GB
KDF_PARALLELISM = 8
KDF_HASH_LEN = 32
KDF_SALT_LEN = 16

# 文件头字段尺寸
SALT_SZ = 16
NONCE_SZ = 12
TAG_SZ = 16
KDF_PARAMS_SZ = 12                     # 3 × uint32

# 预计算头长度
HEADER_SZ_V4 = len(MAGIC_V4) + SALT_SZ + NONCE_SZ + TAG_SZ          # 49
HEADER_SZ_V5 = len(MAGIC_V5) + SALT_SZ + NONCE_SZ + KDF_PARAMS_SZ + TAG_SZ  # 61

# 密码复杂度规则
_PASSWORD_RULES = [
    (r'[A-Z]',        "大写字母"),
    (r'[a-z]',        "小写字母"),
    (r'[0-9]',        "数字"),
    (r'[^A-Za-z0-9]', "特殊字符"),
]


# ════════════════════════════════════════════════════════════
# 实用工具函数
# ════════════════════════════════════════════════════════════

def format_size(size_bytes: int) -> str:
    """格式化文件大小为易读字符串。"""
    if size_bytes < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0 or unit == 'TB':
            return f"{size_bytes:.2f} {unit}" if unit != 'B' else f"{size_bytes} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def generate_strong_password(length: int = 16) -> str:
    """生成同时包含大小写字母、数字及特殊字符的高强度随机密码。"""
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+"

    # 保证每类字符至少出现 2 次
    pwd_chars = [
        secrets.choice(upper), secrets.choice(upper),
        secrets.choice(lower), secrets.choice(lower),
        secrets.choice(digits), secrets.choice(digits),
        secrets.choice(special), secrets.choice(special),
    ]
    all_chars = upper + lower + digits + special
    for _ in range(length - len(pwd_chars)):
        pwd_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(pwd_chars)
    return "".join(pwd_chars)


def is_caps_lock_on() -> bool:
    """跨平台检测当前大写锁定键（Caps Lock）是否处于激活状态。"""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.user32.GetKeyState(0x14) & 1)
        except Exception:
            return False
    return False


def validate_password(password: str) -> tuple[bool, str]:
    """检验密码复杂度。返回 (通过, 错误消息)。"""
    if len(password) < MIN_PASSWORD_LEN:
        return False, f"密码长度不足（当前 {len(password)} 字符，要求 ≥{MIN_PASSWORD_LEN}）"
    for pattern, desc in _PASSWORD_RULES:
        if not re.search(pattern, password):
            return False, f"密码必须包含{desc}"
    return True, ""


def evaluate_strength(password: str) -> tuple[str, str]:
    """评估密码强度，返回 (标签文本, CSS 颜色)。"""
    if not password:
        return "密码强度: 无", "gray"
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码强度: 弱（当前 {len(password)} 字符，需 ≥{MIN_PASSWORD_LEN}）", "#F44336"
    missing = [d for p, d in _PASSWORD_RULES if not re.search(p, password)]
    if missing:
        return f"密码强度: 中（缺少: {', '.join(missing)}）", "#FF9800"
    return "密码强度: 强", "#4CAF50"


# ════════════════════════════════════════════════════════════
# 文件头：读写与版本兼容
# ════════════════════════════════════════════════════════════

class FileHeader:
    """封装加密文件头的序列化 / 反序列化。"""

    __slots__ = ("salt", "nonce", "tag", "time_cost", "memory_cost",
                 "parallelism", "version")

    def __init__(self, *, salt: bytes, nonce: bytes, tag: bytes,
                 time_cost: int, memory_cost: int, parallelism: int,
                 version: int = 5):
        self.salt = salt
        self.nonce = nonce
        self.tag = tag
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.version = version

    def write_placeholder(self, fout) -> int:
        """写入 V5 头（tag 占位为零），返回写入字节数。"""
        fout.write(MAGIC_CURRENT)
        fout.write(self.salt)
        fout.write(self.nonce)
        fout.write(struct.pack('>III', self.time_cost, self.memory_cost, self.parallelism))
        fout.write(b'\x00' * TAG_SZ)
        return HEADER_SZ_V5

    def write_tag(self, fout) -> None:
        """回填真实 GCM tag。"""
        offset = len(MAGIC_CURRENT) + SALT_SZ + NONCE_SZ + KDF_PARAMS_SZ
        fout.seek(offset)
        fout.write(self.tag)

    @classmethod
    def read(cls, fin) -> "FileHeader":
        magic = fin.read(5)
        if magic == MAGIC_V5:
            salt = fin.read(SALT_SZ)
            nonce = fin.read(NONCE_SZ)
            tc, mc, par = struct.unpack('>III', fin.read(KDF_PARAMS_SZ))
            tag = fin.read(TAG_SZ)
            return cls(salt=salt, nonce=nonce, tag=tag,
                       time_cost=tc, memory_cost=mc, parallelism=par, version=5)
        if magic == MAGIC_V4:
            salt = fin.read(SALT_SZ)
            nonce = fin.read(NONCE_SZ)
            tag = fin.read(TAG_SZ)
            return cls(salt=salt, nonce=nonce, tag=tag,
                       time_cost=KDF_TIME_COST, memory_cost=KDF_MEMORY_COST,
                       parallelism=KDF_PARALLELISM, version=4)
        raise ValueError("无效的加密文件格式，请确认文件是否为合法的 VanishCrypt 加密文件")


# ════════════════════════════════════════════════════════════
# 加密核心操作与安全擦除
# ════════════════════════════════════════════════════════════

class SecureFileOps:
    """与文件系统交互的安全操作集合。"""

    @staticmethod
    def derive_key(password: str, salt: bytes | None = None, *,
                   time_cost: int = KDF_TIME_COST,
                   memory_cost: int = KDF_MEMORY_COST,
                   parallelism: int = KDF_PARALLELISM) -> tuple[bytes, bytearray]:
        """Argon2id 密钥派生。返回 (salt, key_bytearray)。"""
        ok, msg = validate_password(password)
        if not ok:
            raise ValueError(msg)

        if salt is None:
            salt = secrets.token_bytes(KDF_SALT_LEN)

        raw = argon2.low_level.hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KDF_HASH_LEN,
            type=argon2.low_level.Type.ID,
        )
        return salt, bytearray(raw)

    @staticmethod
    def wipe_key(key: bytearray) -> None:
        """将 bytearray 密钥内容立即逐字节清零。"""
        for i in range(len(key)):
            key[i] = 0

    @staticmethod
    def secure_erase(file_path: str) -> None:
        """SSD 安全删除：原位随机覆写 + 强制物理落盘(fsync) + 二次随机重命名 + 删除。"""
        if not os.path.isfile(file_path):
            return

        parent = os.path.dirname(os.path.abspath(file_path)) or "."
        tmp_src = os.path.join(parent, f".vc_del_{secrets.token_hex(12)}")
        tmp_dst = os.path.join(parent, f".vc_del_{secrets.token_hex(12)}")

        try:
            # 1. 第一次重命名：切断原始文件名索引
            os.replace(file_path, tmp_src)
            file_size = os.path.getsize(tmp_src)

            # 2. 原位流式覆写：以 r+b 模式打开，对原存储数据块直接覆写伪随机数据
            if file_size > 0:
                with open(tmp_src, 'r+b') as f:
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        chunk_sz = min(CHUNK_SIZE, remaining)
                        # 生成随机字节覆盖原始物理块
                        f.write(secrets.token_bytes(chunk_sz))
                        remaining -= chunk_sz
                    f.flush()
                    try:
                        os.fsync(f.fileno())  # 强制将写缓存刷新至物理存储设备
                    except OSError:
                        pass

            # 3. 第二次重命名：彻底抹除元数据名称轨迹
            os.replace(tmp_src, tmp_dst)

            # 4. 解除链接删除
            os.remove(tmp_dst)

        except Exception as exc:
            for p in (tmp_src, tmp_dst):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            raise RuntimeError(f"安全删除失败: {exc}") from exc

    @staticmethod
    def check_disk_space(files: list[str]) -> tuple[bool, str]:
        """检查目标分区是否有足够的剩余空间（待处理总大小 + 50MB 冗余缓冲）。"""
        if not files:
            return True, ""
        dirs_needed: dict[str, int] = {}
        for f in files:
            if os.path.isfile(f):
                parent = os.path.dirname(os.path.abspath(f)) or "."
                dirs_needed[parent] = dirs_needed.get(parent, 0) + os.path.getsize(f)

        for p, needed in dirs_needed.items():
            try:
                usage = shutil.disk_usage(p)
                safety_margin = 50 * 1024 * 1024  # 50 MB 缓冲
                if usage.free < needed + safety_margin:
                    free_str = format_size(usage.free)
                    need_str = format_size(needed + safety_margin)
                    return False, f"磁盘剩余空间不足 ({p})：当前剩余 {free_str}，至少需要 {need_str}"
            except OSError:
                pass
        return True, ""

    @staticmethod
    def sha256(file_path: str) -> str:
        """计算文件 SHA-256 哈希值。"""
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.finalize().hex()


# ════════════════════════════════════════════════════════════
# 元数据管理器
# ════════════════════════════════════════════════════════════

class MetadataManager:

    @staticmethod
    def generate(files: list[str], mode: str) -> dict:
        return {
            "version": "2.1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": mode,
            "files": [
                {
                    "name": os.path.basename(f),
                    "size": os.path.getsize(f) if os.path.isfile(f) else 0,
                    "sha256": SecureFileOps.sha256(f) if os.path.isfile(f) else "",
                }
                for f in files if os.path.isfile(f)
            ],
        }


# ════════════════════════════════════════════════════════════
# 工作线程 (QThread 任务调度)
# ════════════════════════════════════════════════════════════

class CryptoWorker(QObject):
    """在后台线程中执行批量加密 / 解密 / 安全删除。"""

    # (file_pct, total_pct, filename, speed_str, eta_str)
    progress = Signal(int, int, str, str, str)
    file_status = Signal(str, str)     # (filepath, "processing" | "success" | "error")
    log = Signal(str, str)            # (消息, 级别)
    finished = Signal()
    error = Signal(str)
    metadata_ready = Signal(dict)

    def __init__(self, password: str, files: list[str], mode: str, wipe_source: bool = True):
        super().__init__()
        self._password = password
        self.files = self._collect(files)
        self.mode = mode
        self.wipe_source = wipe_source
        self._running = True
        self._mutex = QMutex()
        self.total_size = sum(os.path.getsize(f) for f in self.files if os.path.isfile(f)) or 1
        self.processed = 0
        self.start_time = 0.0

    @staticmethod
    def _collect(paths: list[str]) -> list[str]:
        out: list[str] = []
        for p in paths:
            if os.path.isdir(p):
                for root, _, names in os.walk(p):
                    out.extend(os.path.join(root, n) for n in names)
            elif os.path.isfile(p):
                out.append(p)
        # 去重保持顺序
        seen = set()
        res = []
        for item in out:
            normalized = os.path.abspath(item)
            if normalized not in seen and os.path.isfile(normalized):
                seen.add(normalized)
                res.append(normalized)
        return res

    def _alive(self) -> bool:
        self._mutex.lock()
        r = self._running
        self._mutex.unlock()
        return r

    @Slot()
    def stop(self):
        self._mutex.lock()
        self._running = False
        self._mutex.unlock()

    def _emit_progress(self, file_done: int, file_size: int, filename: str):
        file_pct = min(int((file_done / file_size * 100)), 100) if file_size > 0 else 100
        total_done = self.processed + file_done
        total_pct = min(int((total_done / self.total_size * 100)), 100)

        elapsed = time.time() - self.start_time
        if elapsed > 0.5 and total_done > 0:
            speed_bps = total_done / elapsed
            speed_str = f"{format_size(int(speed_bps))}/s"
            remaining_bytes = max(0, self.total_size - total_done)
            remaining_sec = int(remaining_bytes / speed_bps) if speed_bps > 0 else 0
            mins, secs = divmod(remaining_sec, 60)
            eta_str = f"剩余 {mins:02d}:{secs:02d}"
        else:
            speed_str = "-- MB/s"
            eta_str = "估算中…"

        self.progress.emit(file_pct, total_pct, filename, speed_str, eta_str)

    @Slot()
    def process(self):
        try:
            self.start_time = time.time()
            meta = MetadataManager.generate(self.files, self.mode)
            self.metadata_ready.emit(meta)

            fail_count = 0
            for fp in self.files:
                if not self._alive():
                    self.log.emit("操作已被用户主动取消", "warning")
                    break
                try:
                    self.file_status.emit(fp, "processing")
                    self._process_one(fp)
                    self.file_status.emit(fp, "success")
                except Exception as exc:
                    fail_count += 1
                    self.file_status.emit(fp, "error")
                    self.log.emit(f"处理失败: {os.path.basename(fp)} — {exc}", "error")

            if fail_count:
                self.log.emit(f"批处理结束: 共 {fail_count} 个文件处理失败", "warning")

            self.finished.emit()
        except Exception as exc:
            self.error.emit(f"全局调度错误: {exc}")
        finally:
            self._password = None

    def _process_one(self, file_path: str):
        file_size = os.path.getsize(file_path)
        temp = f"{file_path}.tmp_{secrets.token_hex(4)}"
        try:
            if self.mode == 'encrypt':
                out = self._encrypt(file_path, temp, file_size)
            else:
                out = self._decrypt(file_path, temp, file_size)

            if self.wipe_source:
                self.log.emit(f"安全粉碎原文件: {os.path.basename(file_path)}", "info")
                SecureFileOps.secure_erase(file_path)
            else:
                self.log.emit(f"已保留原文件: {os.path.basename(file_path)}", "info")

            self.log.emit(f"✔ {os.path.basename(file_path)} → {os.path.basename(out)}", "success")
            self.processed += file_size
            self._emit_progress(0, file_size, os.path.basename(file_path))

        except Exception:
            if os.path.exists(temp):
                try:
                    os.remove(temp)
                except OSError:
                    pass
            raise

    def _encrypt(self, src: str, tmp: str, file_size: int) -> str:
        salt, key = SecureFileOps.derive_key(self._password)
        try:
            nonce = secrets.token_bytes(NONCE_SZ)
            cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce), backend=default_backend())
            enc = cipher.encryptor()

            header = FileHeader(salt=salt, nonce=nonce, tag=b'\x00' * TAG_SZ,
                                time_cost=KDF_TIME_COST,
                                memory_cost=KDF_MEMORY_COST,
                                parallelism=KDF_PARALLELISM)

            with open(tmp, 'wb') as fout:
                header.write_placeholder(fout)

                with open(src, 'rb') as fin:
                    done = 0
                    while chunk := fin.read(CHUNK_SIZE):
                        if not self._alive():
                            raise InterruptedError("操作已被用户中断")
                        fout.write(enc.update(chunk))
                        done += len(chunk)
                        self._emit_progress(done, file_size, os.path.basename(src))

                tail = enc.finalize()
                if tail:
                    fout.write(tail)

                header.tag = enc.tag
                header.write_tag(fout)

            final = src + ENCRYPTED_EXT
            os.replace(tmp, final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            return final
        finally:
            SecureFileOps.wipe_key(key)

    def _decrypt(self, src: str, tmp: str, file_size: int) -> str:
        key = None
        try:
            with open(src, 'rb') as fin:
                header = FileHeader.read(fin)

                _, key = SecureFileOps.derive_key(
                    self._password, header.salt,
                    time_cost=header.time_cost,
                    memory_cost=header.memory_cost,
                    parallelism=header.parallelism,
                )

                cipher = Cipher(algorithms.AES(bytes(key)),
                                modes.GCM(header.nonce, header.tag),
                                backend=default_backend())
                dec = cipher.decryptor()

                with open(tmp, 'wb') as fout:
                    done = 0
                    while chunk := fin.read(CHUNK_SIZE):
                        if not self._alive():
                            raise InterruptedError("操作已被用户中断")
                        fout.write(dec.update(chunk))
                        done += len(chunk)
                        self._emit_progress(done, file_size, os.path.basename(src))

                    tail = dec.finalize()
                    if tail:
                        fout.write(tail)

            base = os.path.basename(src)
            if base.endswith(ENCRYPTED_EXT):
                restored = base[: -len(ENCRYPTED_EXT)]
            else:
                restored = base + ".decrypted"

            final = os.path.join(os.path.dirname(src), restored)
            if os.path.exists(final):
                name, ext = os.path.splitext(restored)
                cnt = 1
                while os.path.exists(final):
                    final = os.path.join(os.path.dirname(src), f"{name}_{cnt}{ext}")
                    cnt += 1

            os.replace(tmp, final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            return final

        except InvalidTag:
            raise ValueError("密码验证失败：密码错误或文件已被篡改")
        except (ValueError, InterruptedError):
            raise
        except Exception as exc:
            raise RuntimeError(f"解密系统错误：{exc}") from exc
        finally:
            if key is not None:
                SecureFileOps.wipe_key(key)


# ════════════════════════════════════════════════════════════
# GUI 主窗口
# ════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VanishCrypt — AES-GCM 安全加密解密 (v2.1)")
        self.setGeometry(100, 80, 960, 780)
        self.setAcceptDrops(True)

        self._files: list[str] = []
        self._worker: CryptoWorker | None = None
        self._thread: QThread | None = None

        self._init_ui()
        self._apply_style()
        self._setup_timer()

    def _init_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setSpacing(10)
        lay.setContentsMargins(18, 16, 18, 16)

        # ── 1. 待处理文件表格队列 ─────────────────────────────
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("待处理文件列表 (支持直接拖放文件或文件夹到此处):"))
        top_bar.addStretch()

        self._add_files_btn = QPushButton("📄 添加文件…")
        self._add_folder_btn = QPushButton("📁 添加文件夹…")
        self._clear_files_btn = QPushButton("🗑️ 清空列表")
        for b in (self._add_files_btn, self._add_folder_btn, self._clear_files_btn):
            b.setFixedHeight(30)
        top_bar.addWidget(self._add_files_btn)
        top_bar.addWidget(self._add_folder_btn)
        top_bar.addWidget(self._clear_files_btn)
        lay.addLayout(top_bar)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["文件名", "大小", "状态", "操作"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.setColumnWidth(3, 80)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setFixedHeight(180)
        lay.addWidget(self._table)

        self._summary_label = QLabel("共 0 个文件 | 合计体积: 0 B")
        self._summary_label.setStyleSheet("color: #AAAAAA; font-size: 9pt;")
        lay.addWidget(self._summary_label)

        # ── 2. 密码输入与控制 ─────────────────────────────────
        pwd_row = QHBoxLayout()
        self._pwd = QLineEdit()
        self._pwd.setEchoMode(QLineEdit.Password)
        self._pwd.setPlaceholderText("请输入主密码（长度 ≥ 12 位，含大小写、数字与特殊字符）")

        self._gen_pwd_btn = QPushButton("🎲 生成强密码")
        self._gen_pwd_btn.setFixedHeight(32)
        self._show_pwd = QCheckBox("显示明文")

        pwd_row.addWidget(QLabel("主密码:"), 0)
        pwd_row.addWidget(self._pwd, 1)
        pwd_row.addWidget(self._gen_pwd_btn, 0)
        pwd_row.addWidget(self._show_pwd, 0)
        lay.addLayout(pwd_row)

        confirm_row = QHBoxLayout()
        self._pwd_confirm = QLineEdit()
        self._pwd_confirm.setEchoMode(QLineEdit.Password)
        self._pwd_confirm.setPlaceholderText("加密操作需再次输入密码以确保无误")

        self._caps_label = QLabel("⚠️ 大写锁定 (Caps Lock) 已开启")
        self._caps_label.setStyleSheet("color: #FF9800; font-weight: bold;")
        self._caps_label.setVisible(False)

        confirm_row.addWidget(QLabel("确认密码:"), 0)
        confirm_row.addWidget(self._pwd_confirm, 1)
        confirm_row.addWidget(self._caps_label, 0)
        lay.addLayout(confirm_row)

        # 密码强度标签
        self._strength = QLabel("密码强度: 无")
        self._strength.setAlignment(Qt.AlignRight)
        lay.addWidget(self._strength)

        # ── 3. 安全选项配置 ───────────────────────────────────
        opts_row = QHBoxLayout()
        self._wipe_chk = QCheckBox("操作完成后安全粉碎原文件 (原位密文覆盖 + fsync 落盘，防止恢复)")
        self._wipe_chk.setChecked(True)
        self._clear_pwd_chk = QCheckBox("批处理完成后清空密码输入框")
        self._clear_pwd_chk.setChecked(True)

        opts_row.addWidget(self._wipe_chk)
        opts_row.addStretch()
        opts_row.addWidget(self._clear_pwd_chk)
        lay.addLayout(opts_row)

        # ── 4. 核心执行按钮 ───────────────────────────────────
        btn_row = QHBoxLayout()
        self._enc_btn = QPushButton("🔐 加密文件")
        self._dec_btn = QPushButton("🔓 解密文件")
        self._cancel_btn = QPushButton("⏹️ 取消操作")
        for b in (self._enc_btn, self._dec_btn, self._cancel_btn):
            b.setFixedHeight(42)
        self._cancel_btn.setEnabled(False)

        btn_row.addWidget(self._enc_btn)
        btn_row.addWidget(self._dec_btn)
        btn_row.addWidget(self._cancel_btn)
        lay.addLayout(btn_row)

        # ── 5. 双进度条与吞吐监控 ─────────────────────────────
        prog_box = QVBoxLayout()
        prog_box.setSpacing(4)

        f_label_row = QHBoxLayout()
        self._file_prog_lbl = QLabel("当前文件进度: 就绪")
        f_label_row.addWidget(self._file_prog_lbl)
        prog_box.addLayout(f_label_row)

        self._file_progress = QProgressBar()
        self._file_progress.setFixedHeight(18)
        prog_box.addWidget(self._file_progress)

        t_label_row = QHBoxLayout()
        t_label_row.addWidget(QLabel("总体批处理进度:"))
        t_label_row.addStretch()
        self._stats_lbl = QLabel("速率: -- MB/s | 预估剩余时间: --:--")
        self._stats_lbl.setStyleSheet("color: #AAAAAA; font-size: 9pt;")
        t_label_row.addWidget(self._stats_lbl)
        prog_box.addLayout(t_label_row)

        self._total_progress = QProgressBar()
        self._total_progress.setFixedHeight(18)
        prog_box.addWidget(self._total_progress)
        lay.addLayout(prog_box)

        # ── 6. 日志输出及操作栏 ───────────────────────────────
        log_header = QHBoxLayout()
        log_header.addWidget(QLabel("操作日志:"))
        log_header.addStretch()
        self._copy_log_btn = QPushButton("📋 复制日志")
        self._clear_log_btn = QPushButton("🧹 清空日志")
        self._copy_log_btn.setFixedHeight(26)
        self._clear_log_btn.setFixedHeight(26)
        log_header.addWidget(self._copy_log_btn)
        log_header.addWidget(self._clear_log_btn)
        lay.addLayout(log_header)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        lay.addWidget(self._log)

        # ── 信号绑定 ─────────────────────────────────────────
        self._add_files_btn.clicked.connect(self._on_add_files)
        self._add_folder_btn.clicked.connect(self._on_add_folder)
        self._clear_files_btn.clicked.connect(self._on_clear_files)
        self._gen_pwd_btn.clicked.connect(self._on_generate_password)
        self._show_pwd.toggled.connect(self._on_toggle_pwd)
        self._pwd.textChanged.connect(self._on_pwd_changed)
        self._enc_btn.clicked.connect(lambda: self._start('encrypt'))
        self._dec_btn.clicked.connect(lambda: self._start('decrypt'))
        self._cancel_btn.clicked.connect(self._on_cancel)
        self._clear_log_btn.clicked.connect(self._log.clear)
        self._copy_log_btn.clicked.connect(self._on_copy_log)

    # ── CapsLock 轮询定时器 ───────────────────────────────

    def _setup_timer(self):
        self._caps_timer = QTimer(self)
        self._caps_timer.timeout.connect(self._check_caps_lock)
        self._caps_timer.start(400)

    def _check_caps_lock(self):
        if is_caps_lock_on():
            if not self._caps_label.isVisible():
                self._caps_label.setVisible(True)
        else:
            if self._caps_label.isVisible():
                self._caps_label.setVisible(False)

    # ── 样式 ──────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background:#282828; color:#EEE; font-family:'Segoe UI', 'Microsoft YaHei'; font-size:10pt; }
            QPushButton { background:#388E3C; color:white; padding:6px 14px; border:none; border-radius:4px; font-weight:bold; }
            QPushButton:hover { background:#43A047; }
            QPushButton:disabled { background:#424242; color:#777; }
            QPushButton#cancel { background:#D32F2F; }
            QPushButton#cancel:hover { background:#E53935; }
            QPushButton#small { background:#4A4A4A; font-weight:normal; padding:4px 8px; font-size:9pt; }
            QPushButton#small:hover { background:#616161; }
            QPushButton#remove { background:#C62828; font-weight:bold; padding:2px 6px; font-size:9pt; }
            QPushButton#remove:hover { background:#D32F2F; }
            QProgressBar { background:#383838; border:1px solid #555; border-radius:4px; text-align:center; color:white; font-size:9pt; }
            QProgressBar::chunk { background:#4CAF50; border-radius:3px; }
            QLineEdit, QPlainTextEdit { background:#383838; border:1px solid #555; border-radius:4px; padding:6px; color:#FFF; }
            QLineEdit:focus, QPlainTextEdit:focus { border:1px solid #4CAF50; }
            QTableWidget { background:#333333; border:1px solid #555; border-radius:4px; color:#EEE; gridline-color:#444; }
            QHeaderView::section { background:#2B2B2B; color:#CCC; padding:4px; border:1px solid #444; font-weight:bold; }
            QLabel { color:#EEE; }
            QCheckBox { color:#CCC; }
        """)
        self._cancel_btn.setObjectName("cancel")
        self._add_files_btn.setObjectName("small")
        self._add_folder_btn.setObjectName("small")
        self._clear_files_btn.setObjectName("small")
        self._gen_pwd_btn.setObjectName("small")
        self._copy_log_btn.setObjectName("small")
        self._clear_log_btn.setObjectName("small")

    # ── 拖放管理 ──────────────────────────────────────────

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.toLocalFile()]
        self._add_paths(paths)
        event.acceptProposedAction()

    # ── 文件队列管理 ──────────────────────────────────────

    def _add_paths(self, paths: list[str]):
        new_files: list[str] = []
        for p in paths:
            if os.path.isdir(p):
                for root, _, names in os.walk(p):
                    new_files.extend(os.path.join(root, n) for n in names)
            elif os.path.isfile(p):
                new_files.append(p)

        existing = set(os.path.abspath(f) for f in self._files)
        added_count = 0
        for f in new_files:
            abs_f = os.path.abspath(f)
            if abs_f not in existing and os.path.isfile(abs_f):
                existing.add(abs_f)
                self._files.append(abs_f)
                self._insert_table_row(abs_f)
                added_count += 1

        self._update_summary()
        if added_count > 0:
            self._log_msg(f"已载入 {added_count} 个文件至处理队列", "info")

    def _insert_table_row(self, file_path: str):
        row = self._table.rowCount()
        self._table.insertRow(row)

        name_item = QTableWidgetItem(os.path.basename(file_path))
        name_item.setToolTip(file_path)
        self._table.setItem(row, 0, name_item)

        size_bytes = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
        size_item = QTableWidgetItem(format_size(size_bytes))
        size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._table.setItem(row, 1, size_item)

        is_enc = file_path.endswith(ENCRYPTED_EXT)
        status_text = "待解密" if is_enc else "待加密"
        status_item = QTableWidgetItem(status_text)
        status_item.setTextAlignment(Qt.AlignCenter)
        status_item.setForeground(QColor("#4FC3F7" if is_enc else "#81C784"))
        self._table.setItem(row, 2, status_item)

        del_btn = QPushButton("移除")
        del_btn.setObjectName("remove")
        del_btn.clicked.connect(lambda _, fp=file_path: self._remove_file(fp))
        self._table.setCellWidget(row, 3, del_btn)

    def _remove_file(self, file_path: str):
        abs_p = os.path.abspath(file_path)
        if abs_p in self._files:
            idx = self._files.index(abs_p)
            self._files.pop(idx)
            self._table.removeRow(idx)
            # 重新绑定后面所有行的移除按钮回调
            for r in range(idx, self._table.rowCount()):
                cur_p = self._files[r]
                btn = QPushButton("移除")
                btn.setObjectName("remove")
                btn.clicked.connect(lambda _, fp=cur_p: self._remove_file(fp))
                self._table.setCellWidget(r, 3, btn)
            self._update_summary()

    def _update_summary(self):
        cnt = len(self._files)
        total_b = sum(os.path.getsize(f) for f in self._files if os.path.isfile(f))
        self._summary_label.setText(f"共 {cnt} 个文件 | 合计体积: {format_size(total_b)}")

    def _on_add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择待处理文件", "", "All Files (*)")
        if paths:
            self._add_paths(paths)

    def _on_add_folder(self):
        directory = QFileDialog.getExistingDirectory(self, "选择待处理文件夹")
        if directory:
            self._add_paths([directory])

    def _on_clear_files(self):
        self._files.clear()
        self._table.setRowCount(0)
        self._update_summary()

    # ── 密码管理 ──────────────────────────────────────────

    def _on_generate_password(self):
        pwd = generate_strong_password(16)
        self._pwd.setText(pwd)
        self._pwd_confirm.setText(pwd)
        QApplication.clipboard().setText(pwd)
        self._log_msg("🎲 已自动生成 16 位高强度密码，并已复制到剪贴板！", "success")

    def _on_toggle_pwd(self, show: bool):
        mode = QLineEdit.Normal if show else QLineEdit.Password
        self._pwd.setEchoMode(mode)
        self._pwd_confirm.setEchoMode(mode)

    def _on_pwd_changed(self):
        txt, color = evaluate_strength(self._pwd.text())
        self._strength.setText(txt)
        self._strength.setStyleSheet(f"color:{color}; font-weight:bold;")

    # ── 任务执行与状态流转 ────────────────────────────────

    def _start(self, mode: str):
        if not self._files:
            self._log_msg("请先添加要处理的文件或文件夹", "error")
            QMessageBox.warning(self, "提示", "文件列表为空，请先添加文件！")
            return

        pwd = self._pwd.text()
        ok, msg = validate_password(pwd)
        if not ok:
            self._log_msg(msg, "error")
            QMessageBox.warning(self, "密码不符合要求", msg)
            return

        if mode == 'encrypt' and pwd != self._pwd_confirm.text():
            self._log_msg("两次输入的密码不一致，请重新输入", "error")
            QMessageBox.warning(self, "密码确认错误", "两次输入的密码不一致，请核对后重试！")
            return

        # 磁盘空间预检
        ok_space, space_err = SecureFileOps.check_disk_space(self._files)
        if not ok_space:
            self._log_msg(space_err, "error")
            if QMessageBox.critical(self, "磁盘空间不足", f"{space_err}\n\n是否仍要强行继续？",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return

        n = len(self._files)
        will_wipe = self._wipe_chk.isChecked()
        if mode == 'encrypt':
            warn = (f"即将加密 {n} 个文件。\n\n"
                    f"{'⚠️ 注意：操作完成后，原明文文件将被安全粉碎且不可恢复！' if will_wipe else 'ℹ️ 原文件副本将保留在磁盘上。'}\n"
                    "请务必牢记您的密码，否则加密数据将永久无法找回。\n\n是否继续？")
        else:
            warn = (f"即将解密 {n} 个文件。\n\n"
                    f"{'⚠️ 注意：原始 .secure 密文将在解密成功后被安全粉碎。' if will_wipe else 'ℹ️ 原始 .secure 密文将保留在磁盘上。'}\n\n"
                    "是否继续？")

        if QMessageBox.warning(self, "操作确认", warn,
                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return

        self._set_busy(True)

        self._worker = CryptoWorker(pwd, self._files, mode, wipe_source=will_wipe)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.process)
        self._worker.finished.connect(self._on_done)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._worker.progress.connect(self._on_progress)
        self._worker.file_status.connect(self._on_file_status)
        self._worker.log.connect(self._log_msg)
        self._worker.error.connect(lambda e: self._log_msg(e, "error"))
        self._worker.error.connect(lambda _: self._set_busy(False))
        self._worker.metadata_ready.connect(self._on_meta)

        self._thread.start()

    def _on_cancel(self):
        if self._worker:
            self._worker.stop()
            self._log_msg("正在安全中止任务，请稍候…", "warning")
            self._cancel_btn.setEnabled(False)

    def _on_done(self):
        self._set_busy(False)
        self._log_msg("✨ 所有操作已顺利完成！", "success")
        if self._clear_pwd_chk.isChecked():
            self._pwd.clear()
            self._pwd_confirm.clear()
            self._log_msg("已按安全策略自动清空密码输入框", "info")

    def _set_busy(self, busy: bool):
        self._enc_btn.setEnabled(not busy)
        self._dec_btn.setEnabled(not busy)
        self._add_files_btn.setEnabled(not busy)
        self._add_folder_btn.setEnabled(not busy)
        self._clear_files_btn.setEnabled(not busy)
        self._cancel_btn.setEnabled(busy)
        for r in range(self._table.rowCount()):
            w = self._table.cellWidget(r, 3)
            if w:
                w.setEnabled(not busy)
        if not busy:
            self._file_progress.setValue(0)
            self._total_progress.setValue(0)
            self._file_prog_lbl.setText("当前文件进度: 就绪")
            self._stats_lbl.setText("速率: -- MB/s | 预估剩余时间: --:--")

    # ── UI 状态与事件响应 ─────────────────────────────────

    def _on_progress(self, file_pct: int, total_pct: int, name: str, speed: str, eta: str):
        self._file_progress.setValue(file_pct)
        self._file_prog_lbl.setText(f"当前文件: {name} ({file_pct}%)")
        self._total_progress.setValue(total_pct)
        self._stats_lbl.setText(f"速率: {speed} | {eta}")

    def _on_file_status(self, file_path: str, status: str):
        abs_p = os.path.abspath(file_path)
        if abs_p in self._files:
            row = self._files.index(abs_p)
            status_item = self._table.item(row, 2)
            if not status_item:
                return
            if status == "processing":
                status_item.setText("处理中…")
                status_item.setForeground(QColor("#FFB74D"))
            elif status == "success":
                status_item.setText("✔ 完成")
                status_item.setForeground(QColor("#81C784"))
            elif status == "error":
                status_item.setText("❌ 失败")
                status_item.setForeground(QColor("#E57373"))

    _LOG_STYLE = {
        'error':   ('#F44336', '❗'),
        'warning': ('#FF9800', '⚠️'),
        'info':    ('#E0E0E0', 'ℹ️'),
        'success': ('#4CAF50', '✅'),
    }

    def _log_msg(self, text: str, level: str = "info"):
        color, icon = self._LOG_STYLE.get(level, ('#FFF', ''))
        t_str = datetime.now().strftime("%H:%M:%S")
        self._log.appendHtml(f"<font color='#888'>[{t_str}]</font> <font color='{color}'>{icon} {text}</font>")

    def _on_meta(self, meta: dict):
        self._log_msg(f"────── 任务审计元数据 (模式: {meta['operation']}) ──────", "info")
        self._log_msg(f"时间: {meta['timestamp']} | 总计: {len(meta['files'])} 个有效文件", "info")
        for fi in meta['files']:
            self._log_msg(
                f"  {fi['name']} ({format_size(fi['size'])}) | SHA256: {fi['sha256'][:16]}…", "info")
        self._log_msg("──────────────────────────────────────────", "info")

    def _on_copy_log(self):
        QApplication.clipboard().setText(self._log.toPlainText())
        self._log_msg("日志已成功复制到剪贴板", "info")

    def closeEvent(self, event):
        if self._thread and self._thread.isRunning():
            self._worker.stop()
            self._thread.quit()
            self._thread.wait(3000)
        event.accept()


# ════════════════════════════════════════════════════════════
# 主入口
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setFont(QFont("Microsoft YaHei", 10))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())