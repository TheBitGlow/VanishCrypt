# VanishCrypt

基于 PySide6 的 AES-256-GCM 文件加密解密工具，操作完成后安全擦除原始文件。

## ✨ 功能特性

| 功能 | 说明 |
|------|------|
| 🔐 AES-256-GCM | 认证加密，同时保障机密性与完整性 |
| 🔑 Argon2id 密钥派生 | `time_cost=12`, `memory_cost=1GB`, `parallelism=8` |
| 🗑️ SSD 安全删除 | AES-GCM 加密覆盖 + 二次随机重命名 + 删除 |
| 📁 批量处理 | 支持多文件选择与目录递归 |
| 🖱️ 拖放支持 | 直接拖放文件到窗口 |
| 🔒 密码复杂度 | 最少 12 字符，含大小写、数字、特殊字符 |
| ✅ 双重确认 | 加密时需二次输入密码；操作前弹窗确认 |
| ⏹️ 可取消 | 操作进行中可随时取消 |
| 📊 实时进度 | 逐文件进度条 + 密码强度指示器 |

## 🔒 安全设计

- **密钥管理**：密钥以 `bytearray` 存储，使用后立即清零
- **后端校验**：密码复杂度在 GUI 和加密引擎中双重验证
- **原子操作**：使用 `os.replace()` 确保文件替换原子性（兼容 Windows）
- **异常安全**：临时文件在异常时自动清理，单文件失败不中断批次
- **权限控制**：生成文件权限设为 `0o600`
- **防篡改**：GCM 认证标签验证数据完整性

## 📄 文件格式

### V5 格式 (SECv5) — 当前版本

```
偏移    大小     字段
0       5       MAGIC ('SECv5')
5       16      salt
21      12      nonce
33      4       time_cost   (uint32 big-endian)
37      4       memory_cost (uint32 big-endian)
41      4       parallelism (uint32 big-endian)
45      16      GCM tag
61      ...     加密数据
```

**总头长度：61 字节**

KDF 参数嵌入文件头，确保未来调整参数后旧文件仍可解密。

### V4 兼容

程序可自动识别并解密旧版 `SECv4` 格式文件（使用硬编码 KDF 参数）。

## 🚀 安装与使用

### 环境要求

- Python ≥ 3.10
- Windows / macOS / Linux

### 安装

```bash
pip install -r requirements.txt
```

### 运行

```bash
python VanishCrypt.py
```

## 📦 依赖

| 包 | 最低版本 | 用途 |
|----|---------|------|
| PySide6 | 6.5 | GUI 框架 |
| cryptography | 41.0 | AES-GCM 加密 |
| argon2-cffi | 23.1 | Argon2id 密钥派生 |

## ⚠️ 已知局限

1. **SSD 物理局限**：由于 SSD 的磨损均衡和垃圾回收机制，软件层面的安全擦除无法保证数据在物理介质上完全不可恢复。对高安全需求场景，建议配合全盘加密（如 BitLocker / LUKS）使用。

2. **Python 字符串不可变**：密码作为 Python `str` 传入时无法被安全覆盖。程序在密钥派生后尽力清除引用，但不能保证内存中无残留。

3. **大文件性能**：Argon2id 配置为高强度参数（1GB 内存），每个文件独立派生密钥，批量处理大量文件时可能较慢。

## 📐 架构

```
VanishCrypt.py
├── 常量定义 (CHUNK_SIZE, MAGIC, KDF 参数等)
├── validate_password() / evaluate_strength()  ← 统一密码验证
├── FileHeader                                 ← 文件头序列化 / V4+V5 兼容
├── SecureFileOps                              ← 密钥派生 / 安全擦除 / SHA256
├── MetadataManager                            ← 操作元数据生成
├── CryptoWorker(QObject)                      ← 后台线程加密解密
├── MainWindow(QMainWindow)                    ← PySide6 GUI
└── __main__                                   ← 入口
```

## 📝 License

MIT
