# keybox-tools

为 [Tricky Store](https://github.com/5ec1cff/TrickyStore) 提供的 Android Key Attestation 工具脚本，支持从公开来源获取和检查 `keybox.xml` 的有效性。

## 项目结构

```text
.
├── check.py          # keybox 检查脚本（Python）
├── yuri.sh           # 获取脚本（来源 1）
├── MeowDump.sh       # 获取脚本（来源 2）
├── TrickyAddon.sh    # 获取脚本（来源 3）
└── res/
    ├── google.pem     # Google 硬件证明根公钥（匹配结果：google）
    ├── aosp_ec.pem    # AOSP 软件证明 EC 根公钥（匹配结果：aosp_ec）
    ├── aosp_rsa.pem   # AOSP 软件证明 RSA 根公钥（匹配结果：aosp_rsa）
    ├── knox.pem       # Samsung Knox 证明根公钥（匹配结果：knox）
    └── status.json    # 吊销状态本地后备数据（在线失败时回退）
```

## 检查脚本（`check.py`）

- 解析 XML 中所有可检测的 `Keybox/Key`
- 验证证书链签名关系（RSA/ECDSA）与颁发者链路
- 识别根证书类型（Google / AOSP EC / AOSP RSA / Knox / Unknown）
- 检查私钥是否可解析、是否与叶子证书公钥匹配
- 检查叶子证书有效期（UTC）
- 查询吊销状态：优先 Google 在线接口，失败回退本地 `res/status.json`
- 支持单文件检查和目录批量检查（目录模式不递归）

本脚本的实现参考了以下项目：
- <https://github.com/KimmyXYC/KeyboxChecker>
- <https://github.com/SenyxLois/KeyboxCheckerPython>

### 安装依赖

- Python 3.8+
- `requests`
- `cryptography`

Termux 示例：

```bash
pkg install python python-cryptography
pip install requests
```

### 使用方法

检查单个 XML：

```bash
python3 check.py ./keybox.xml
```

检查目录下所有 `.xml`（不递归）：

```bash
python3 check.py ./xmls
```

### 退出码

- `0`：全部通过（无解析失败、无判定无效）
- `1`：存在解析失败或判定无效
- `2`：输入路径不存在，或目录中未找到 `.xml`

## 获取脚本

三个脚本默认输出到 `./keybox.xml`，也支持传入自定义输出路径。

### 脚本来源与解码流程

- `yuri.sh`
  - 来源：<https://github.com/Yurii0307/yurikey>
  - 流程：下载 -> 单层 Base64 解码
- `MeowDump.sh`
  - 来源：<https://github.com/MeowDump/Integrity-Box>
  - 流程：下载 -> 10 层 Base64 解码 -> 十六进制反解 -> ROT13
- `TrickyAddon.sh`
  - 来源：<https://github.com/KOWX712/Tricky-Addon-Update-Target-List>
  - 流程：下载 -> 十六进制反解 -> Base64 解码

### 安装依赖

- `curl` 或 `wget`
- `base64`
- `xxd`（`MeowDump.sh`、`TrickyAddon.sh` 需要）

Termux 示例：

```bash
pkg install curl wget xxd
```

### 使用方法

```bash
bash yuri.sh [输出路径]
bash MeowDump.sh [输出路径]
bash TrickyAddon.sh [输出路径]
```

查看帮助：

```bash
bash yuri.sh --help
bash MeowDump.sh --help
bash TrickyAddon.sh --help
```

## 注意事项

- `check.py` 依赖同级 `res/` 目录中的 PEM 和 `status.json`，不要删除。
- 获取脚本依赖第三方远程源；源站变更、限流或不可用时可能失败。
- 检查结论仅基于脚本当前规则与数据源，不构成任何官方认证结论。
- 本项目脚本由 AI 生成，仅用于学习与技术研究，请勿用于非法用途。
