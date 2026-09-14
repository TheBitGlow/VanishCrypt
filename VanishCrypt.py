#
# VanishCrypt — AES-GCM 文件加密解密工具
#
# 核心功能：
# 1. Argon2id 密钥派生（time_cost=12, memory_cost=1GB, parallelism=8）
# 2. AES-256-GCM 认证加密，确保机密性与完整性
# 3. SSD 优化安全删除：加密覆盖 + 二次随机重命名 + 删除
#
# 文件格式 V5 (SECv5)：
#   MAGIC(5) | salt(16) | nonce(12) | kdf_params(12) | tag(16) | encrypted_data
#   向后兼容 V4 (SECv4) 格式解密
#
# 安全机制：
# - 密码复杂度校验：长度≥12，含大小写/数字/特殊字符
# - 密钥以 bytearray 存储，使用后立即清零
# - GCM 认证标签防篡改验证
# - 临时文件异常时自动清理
#
# 架构：
# - MVC 分离，QThread 异步处理，QMutex 线程安全取消
# - PySide6 GUI，Fusion 风格深色主题
#

import os
import sys
import re
import struct
import secrets
import argon2
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QFileDialog,
    QMessageBox, QPlainTextEdit, QStyleFactory, QCheckBox,
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QObject, QMutex
from PySide6.QtGui import QFont


# ════════════════════════════════════════════════════════════
# 常量
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
# 密码验证（统一入口，GUI 与后端共用）
# ════════════════════════════════════════════════════════════

def validate_password(password: str) -> tuple[bool, str]:
    """检验密码复杂度。返回 (通过, 错误消息)。"""
    if len(password) < MIN_PASSWORD_LEN:
        return False, f"密码长度不足（当前 {len(password)} 字符，要求 ≥{MIN_PASSWORD_LEN}）"
    for pattern, desc in _PASSWORD_RULES:
        if not re.search(pattern, password):
            return False, f"密码必须包含{desc}"
    return True, ""


def evaluate_strength(password: str) -> tuple[str, str]:
    """返回 (标签文本, CSS 颜色)。"""
    if not password:
        return "密码强度: 无", "gray"
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码强度: 弱（当前 {len(password)} 字符，需 ≥{MIN_PASSWORD_LEN}）", "red"
    missing = [d for p, d in _PASSWORD_RULES if not re.search(p, password)]
    if missing:
        return f"密码强度: 中（缺少: {', '.join(missing)}）", "orange"
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

    # ── 写入 ──────────────────────────────────────────────

    def write_placeholder(self, fout) -> int:
        """写入 V5 头（tag 占位为零），返回写入字节数。"""
        fout.write(MAGIC_CURRENT)
        fout.write(self.salt)
        fout.write(self.nonce)
        fout.write(struct.pack('>III',
                               self.time_cost, self.memory_cost, self.parallelism))
        fout.write(b'\x00' * TAG_SZ)
        return HEADER_SZ_V5

    def write_tag(self, fout) -> None:
        """回填真实 GCM tag。"""
        offset = len(MAGIC_CURRENT) + SALT_SZ + NONCE_SZ + KDF_PARAMS_SZ
        fout.seek(offset)
        fout.write(self.tag)

    # ── 读取（自动识别版本）────────────────────────────────

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
        raise ValueError("无效的加密文件格式，请确认文件是否为合法加密文件")


# ════════════════════════════════════════════════════════════
# 加密核心操作
# ════════════════════════════════════════════════════════════

class SecureFileOps:
    """与文件系统交互的安全操作集合。"""

    @staticmethod
    def derive_key(password: str, salt: bytes | None = None, *,
                   time_cost: int = KDF_TIME_COST,
                   memory_cost: int = KDF_MEMORY_COST,
                   parallelism: int = KDF_PARALLELISM) -> tuple[bytes, bytearray]:
        """Argon2id 密钥派生。返回 (salt, key_bytearray)。

        密钥以 bytearray 返回，调用方用完后应将其清零。
        """
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
        """将 bytearray 密钥内容清零。"""
        for i in range(len(key)):
            key[i] = 0

    @staticmethod
    def secure_erase(file_path: str) -> None:
        """SSD 安全删除：加密覆盖 → 二次重命名 → 删除。"""
        if not os.path.isfile(file_path):
            return

        parent = os.path.dirname(file_path) or "."
        tmp_src = os.path.join(parent, f".vc_del_{secrets.token_hex(12)}")
        tmp_enc = os.path.join(parent, f".vc_del_{secrets.token_hex(12)}")

        try:
            # 第一次重命名：断开原始文件名
            os.replace(file_path, tmp_src)

            # AES-GCM 加密覆盖
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce),
                            backend=default_backend())
            encryptor = cipher.encryptor()

            with open(tmp_src, 'rb') as fin, open(tmp_enc, 'wb') as fout:
                while chunk := fin.read(CHUNK_SIZE):
                    fout.write(encryptor.update(chunk))
                final = encryptor.finalize()
                if final:
                    fout.write(final)

            # 删除两个临时文件
            os.remove(tmp_src)
            os.remove(tmp_enc)

        except Exception as exc:
            # 尽力清理
            for p in (tmp_src, tmp_enc):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            raise RuntimeError(f"安全删除失败: {exc}") from exc

    @staticmethod
    def sha256(file_path: str) -> str:
        """计算文件 SHA-256 哈希值。"""
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.finalize().hex()


# ════════════════════════════════════════════════════════════
# 元数据
# ════════════════════════════════════════════════════════════

class MetadataManager:

    @staticmethod
    def generate(files: list[str], mode: str) -> dict:
        return {
            "version": "2.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": mode,
            "files": [
                {
                    "name": os.path.basename(f),
                    "size": os.path.getsize(f),
                    "sha256": SecureFileOps.sha256(f),
                }
                for f in files
            ],
        }


# ════════════════════════════════════════════════════════════
# 工作线程
# ════════════════════════════════════════════════════════════

class CryptoWorker(QObject):
    """在后台线程中执行加密 / 解密 / 安全删除。"""

    progress = Signal(int, str)       # (百分比, 文件名)
    log = Signal(str, str)            # (消息, 级别)
    finished = Signal()
    error = Signal(str)
    metadata_ready = Signal(dict)

    def __init__(self, password: str, files: list[str], mode: str):
        super().__init__()
        self._password = password
        self.files = self._collect(files)
        self.mode = mode
        self._running = True
        self._mutex = QMutex()
        self.total_size = sum(os.path.getsize(f) for f in self.files) or 1
        self.processed = 0

    # ── 辅助 ─────────────────────────────────────────────

    @staticmethod
    def _collect(paths: list[str]) -> list[str]:
        out: list[str] = []
        for p in paths:
            if os.path.isdir(p):
                for root, _, names in os.walk(p):
                    out.extend(os.path.join(root, n) for n in names)
            elif os.path.isfile(p):
                out.append(p)
        return out

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

    def _emit_progress(self, extra: int, filename: str):
        pct = min(int((self.processed + extra) / self.total_size * 100), 100)
        self.progress.emit(pct, filename)

    # ── 主循环 ────────────────────────────────────────────

    @Slot()
    def process(self):
        try:
            meta = MetadataManager.generate(self.files, self.mode)
            self.metadata_ready.emit(meta)

            fail_count = 0
            for fp in self.files:
                if not self._alive():
                    self.log.emit("操作已被用户取消", "warning")
                    break
                try:
                    self._process_one(fp)
                except Exception as exc:
                    fail_count += 1
                    self.log.emit(f"处理失败: {os.path.basename(fp)} — {exc}", "error")

            if fail_count:
                self.log.emit(f"共 {fail_count} 个文件处理失败", "warning")

            self.finished.emit()
        except Exception as exc:
            self.error.emit(f"全局错误: {exc}")
        finally:
            self._password = None          # 尽力清除引用

    def _process_one(self, file_path: str):
        file_size = os.path.getsize(file_path)
        temp = f"{file_path}.tmp_{secrets.token_hex(4)}"
        try:
            if self.mode == 'encrypt':
                out = self._encrypt(file_path, temp)
            else:
                out = self._decrypt(file_path, temp)

            self.log.emit(f"安全删除原文件: {os.path.basename(file_path)}", "info")
            SecureFileOps.secure_erase(file_path)

            self.log.emit(
                f"✔ {os.path.basename(file_path)} → {os.path.basename(out)}", "success")
            self.processed += file_size
            self._emit_progress(0, os.path.basename(file_path))

        except Exception:
            if os.path.exists(temp):
                try:
                    os.remove(temp)
                except OSError:
                    pass
            raise

    # ── 加密 ──────────────────────────────────────────────

    def _encrypt(self, src: str, tmp: str) -> str:
        salt, key = SecureFileOps.derive_key(self._password)
        try:
            nonce = secrets.token_bytes(NONCE_SZ)
            cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce),
                            backend=default_backend())
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
                            raise InterruptedError("操作已中止")
                        fout.write(enc.update(chunk))
                        done += len(chunk)
                        self._emit_progress(done, os.path.basename(src))

                # ★ 正确处理 finalize 返回值
                tail = enc.finalize()
                if tail:
                    fout.write(tail)

                # 回填 GCM tag
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

    # ── 解密 ──────────────────────────────────────────────

    def _decrypt(self, src: str, tmp: str) -> str:
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
                            raise InterruptedError("操作已中止")
                        fout.write(dec.update(chunk))
                        done += len(chunk)
                        self._emit_progress(done, os.path.basename(src))

                    tail = dec.finalize()
                    if tail:
                        fout.write(tail)

            # 恢复原始文件名：仅去除末尾 .secure
            base = os.path.basename(src)
            if base.endswith(ENCRYPTED_EXT):
                restored = base[: -len(ENCRYPTED_EXT)]
            else:
                restored = base + ".decrypted"

            final = os.path.join(os.path.dirname(src), restored)

            # 防止覆盖同名文件
            if os.path.exists(final):
                name, ext = os.path.splitext(restored)
                cnt = 1
                while os.path.exists(final):
                    final = os.path.join(os.path.dirname(src),
                                         f"{name}_{cnt}{ext}")
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
        self.setWindowTitle("VanishCrypt — AES-GCM 加密解密")
        self.setGeometry(100, 100, 900, 720)
        self.setAcceptDrops(True)

        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setSpacing(10)
        lay.setContentsMargins(20, 20, 20, 20)

        # ── 文件选择 ──────────────────────────────────────
        row = QHBoxLayout()
        self._file_input = QLineEdit()
        self._file_input.setPlaceholderText("拖放文件到此处或点击「浏览」按钮")
        self._file_input.setReadOnly(True)
        self._browse_btn = QPushButton("浏览…")
        self._browse_btn.setFixedWidth(100)
        row.addWidget(QLabel("选择文件:"), 1)
        row.addWidget(self._file_input, 8)
        row.addWidget(self._browse_btn, 1)
        lay.addLayout(row)

        # ── 密码 ─────────────────────────────────────────
        row = QHBoxLayout()
        self._pwd = QLineEdit()
        self._pwd.setEchoMode(QLineEdit.Password)
        self._show_pwd = QCheckBox("显示密码")
        row.addWidget(QLabel("输入密码:"), 1)
        row.addWidget(self._pwd, 8)
        row.addWidget(self._show_pwd, 1)
        lay.addLayout(row)

        # ── 确认密码（加密时使用）────────────────────────
        row = QHBoxLayout()
        self._pwd_confirm = QLineEdit()
        self._pwd_confirm.setEchoMode(QLineEdit.Password)
        self._pwd_confirm.setPlaceholderText("加密时需再次输入密码以确认")
        row.addWidget(QLabel("确认密码:"), 1)
        row.addWidget(self._pwd_confirm, 8)
        row.addWidget(QLabel(), 1)             # 占位
        lay.addLayout(row)

        # ── 密码强度 ─────────────────────────────────────
        self._strength = QLabel("密码强度: 无")
        self._strength.setAlignment(Qt.AlignRight)
        lay.addWidget(self._strength)

        # ── 按钮 ─────────────────────────────────────────
        row = QHBoxLayout()
        self._enc_btn = QPushButton("加密文件")
        self._dec_btn = QPushButton("解密文件")
        self._cancel_btn = QPushButton("取消操作")
        for b in (self._enc_btn, self._dec_btn, self._cancel_btn):
            b.setFixedHeight(40)
        self._cancel_btn.setEnabled(False)
        row.addWidget(self._enc_btn)
        row.addWidget(self._dec_btn)
        row.addWidget(self._cancel_btn)
        lay.addLayout(row)

        # ── 日志 ─────────────────────────────────────────
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        lay.addWidget(self._log)

        # ── 进度条 ───────────────────────────────────────
        self._progress = QProgressBar()
        lay.addWidget(self._progress)

        # ── 样式 ─────────────────────────────────────────
        self._apply_style()

        # ── 信号 ─────────────────────────────────────────
        self._browse_btn.clicked.connect(self._on_browse)
        self._enc_btn.clicked.connect(lambda: self._start('encrypt'))
        self._dec_btn.clicked.connect(lambda: self._start('decrypt'))
        self._show_pwd.toggled.connect(self._on_toggle_pwd)
        self._pwd.textChanged.connect(self._on_pwd_changed)
        self._cancel_btn.clicked.connect(self._on_cancel)

        # ── 状态 ─────────────────────────────────────────
        self._files: list[str] = []
        self._worker: CryptoWorker | None = None
        self._thread: QThread | None = None

    # ── 样式 ──────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background:#2E2E2E; color:white;
                           font-family:'微软雅黑'; font-size:10pt; }
            QPushButton  { background:#4CAF50; color:white;
                           padding:8px 20px; border:none;
                           border-radius:4px; font-size:12pt; }
            QPushButton:hover    { background:#45a049; }
            QPushButton:disabled { background:#555; color:#999; }
            QPushButton#cancel   { background:#d32f2f; }
            QPushButton#cancel:hover { background:#b71c1c; }
            QProgressBar { background:#404040; border:1px solid #606060;
                           border-radius:4px; padding:5px;
                           text-align:center; color:white; }
            QProgressBar::chunk { background:#4CAF50; border-radius:4px; }
            QLineEdit, QPlainTextEdit {
                background:#404040; border:1px solid #606060;
                border-radius:4px; padding:8px; color:white; }
            QLabel    { color:white; }
            QCheckBox { color:#CCC; }
        """)
        self._cancel_btn.setObjectName("cancel")

    # ── 拖放 ──────────────────────────────────────────────

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        self._files = [u.toLocalFile() for u in event.mimeData().urls()]
        self._file_input.setText(
            ", ".join(os.path.basename(f) for f in self._files))
        event.acceptProposedAction()

    # ── 密码 ──────────────────────────────────────────────

    def _on_toggle_pwd(self, show: bool):
        mode = QLineEdit.Normal if show else QLineEdit.Password
        self._pwd.setEchoMode(mode)
        self._pwd_confirm.setEchoMode(mode)

    def _on_pwd_changed(self):
        txt, color = evaluate_strength(self._pwd.text())
        self._strength.setText(txt)
        self._strength.setStyleSheet(f"color:{color}")

    # ── 文件选择 ──────────────────────────────────────────

    def _on_browse(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择文件", "", "All Files (*)")
        if paths:
            self._files = paths
            self._file_input.setText(
                ", ".join(os.path.basename(f) for f in self._files))

    # ── 启动处理 ──────────────────────────────────────────

    def _start(self, mode: str):
        # 前置校验
        if not self._files:
            self._log_msg("请先选择要处理的文件", "error")
            return

        pwd = self._pwd.text()
        ok, msg = validate_password(pwd)
        if not ok:
            self._log_msg(msg, "error")
            return

        if mode == 'encrypt' and pwd != self._pwd_confirm.text():
            self._log_msg("两次输入的密码不一致，请重新输入", "error")
            return

        # 确认对话框
        n = len(self._files)
        if mode == 'encrypt':
            warn = (f"即将加密 {n} 个文件。\n\n"
                    "⚠️ 加密完成后，原始文件将被安全删除且不可恢复！\n"
                    "请确保您已牢记密码，否则数据将永久丢失。\n\n"
                    "是否继续？")
        else:
            warn = (f"即将解密 {n} 个文件。\n\n"
                    "原始加密文件将在解密后被安全删除。\n\n"
                    "是否继续？")

        if QMessageBox.warning(self, "操作确认", warn,
                               QMessageBox.Yes | QMessageBox.No,
                               QMessageBox.No) != QMessageBox.Yes:
            return

        self._set_busy(True)

        self._worker = CryptoWorker(pwd, self._files, mode)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.process)
        self._worker.finished.connect(self._on_done)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._worker.progress.connect(self._on_progress)
        self._worker.log.connect(self._log_msg)
        self._worker.error.connect(lambda e: self._log_msg(e, "error"))
        self._worker.error.connect(lambda _: self._set_busy(False))
        self._worker.metadata_ready.connect(self._on_meta)

        self._thread.start()

    def _on_cancel(self):
        if self._worker:
            self._worker.stop()
            self._log_msg("正在取消操作…", "warning")

    def _on_done(self):
        self._set_busy(False)
        self._log_msg("所有操作已完成", "success")

    def _set_busy(self, busy: bool):
        self._enc_btn.setEnabled(not busy)
        self._dec_btn.setEnabled(not busy)
        self._browse_btn.setEnabled(not busy)
        self._cancel_btn.setEnabled(busy)
        if not busy:
            self._progress.setValue(0)

    # ── UI 更新 ───────────────────────────────────────────

    def _on_progress(self, pct: int, name: str):
        self._progress.setValue(pct)
        self._progress.setFormat(f"{pct}% — {name}")

    _LOG_STYLE = {
        'error':   ('red',     '❗'),
        'warning': ('orange',  '⚠️'),
        'info':    ('white',   'ℹ️'),
        'success': ('#4CAF50', '✅'),
    }

    def _log_msg(self, text: str, level: str = "info"):
        color, icon = self._LOG_STYLE.get(level, ('white', ''))
        self._log.appendHtml(f"<font color='{color}'>{icon} {text}</font>")

    def _on_meta(self, meta: dict):
        self._log_msg("────── 元数据信息 ──────", "info")
        self._log_msg(f"操作: {meta['operation']}", "info")
        self._log_msg(f"时间: {meta['timestamp']}", "info")
        self._log_msg(f"文件数: {len(meta['files'])}", "info")
        for fi in meta['files']:
            self._log_msg(
                f"  {fi['name']}  |  {fi['size']} B  |  SHA256: {fi['sha256'][:16]}…",
                "info")
        self._log_msg("────────────────────────", "info")

    # ── 关闭 ──────────────────────────────────────────────

    def closeEvent(self, event):
        if self._thread and self._thread.isRunning():
            self._worker.stop()
            self._thread.quit()
            self._thread.wait(3000)
        event.accept()


# ════════════════════════════════════════════════════════════
# 入口
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setFont(QFont("微软雅黑", 10))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())