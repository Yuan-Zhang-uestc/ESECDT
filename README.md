# Subscripton-Based Entrust Delivery Experimental Framework / 订阅式托管交付实验框架

This project implements an end-to-end encrypted data delivery process ESECDT leveraging public-key encryption with keyword search (PEKS), proxy re-encryption (PRE), and double ratchet key agreement (DR). It is used ri evaluate the performance of different key management strategies (`trade.py`, `fresh+AE.py`, `naive.py`) in large data transmission scenarios.
该项目实现了一个结合 **公钥可搜索加密**、**代理重加密** 与 **双棘轮密钥协商** 的端到端加密数据交易流程，用于评估不同密钥管理策略（`trade.py`、`fresh+AE.py`、`naive.py`）在大数据传输场景下的性能。

## Directory / 目录结构

| File / 文件 | Description / 说明 |
| --- | --- |
| `trade.py` | Main experiment script for ESECDT, containg the seller, broker, and buyer workflows and timing statistics. / ESECDT方案的主实验脚本。含卖家、经纪人、买家三方流程及耗时统计。 |
| `fresh+AE.py` | Scheme with a persistent shared key + data key re-encryption using authenticated encryption (AE). / 持久共享密钥 + 数据密钥再次加密（Authenticated Encryption）方案。 |
| `naive.py` | A baseline scheme that renegotiates a Diffie-Hellman key in each round. / 每轮重新 Diffie-Hellman 协商的朴素方案，作为对照。 |
| `proxy_re_encrypt_sdk.py` | PRE SDK: key generation, re-encryption key generation, two types of encryption/decryption processes. / PRE SDK：含密钥生成、重加密密钥生成、两种加/解密流程。 |
| `peks.py` | PEKS toolkit: keyword hashing, signing, trapdoor construction, etc. / PEKS 工具集：关键词哈希、签名、Trapdoor 构造等。 |
| `data.py` | Random data generation, by default producing a hexadecimal string of specified length. / 随机数据生成，默认产生指定位数的十六进制串。 |
| `verify_curve_points.py` | Script to verify the length of elliptic curve points, sampling multiple rounds to confirm the encoding length of G1/G2 points. / 曲线点长度验证脚本，多轮抽样确认 G1/G2 点的编码长度。 |
| `curve_point_verification.md` | Records the steps and outputs of elliptic curve point verification. / 记录椭圆曲线点验证步骤及输出。 |
| `11-15/` | Locally packaged Python dependencies (including bplib, petlib, etc.), no global installation required. / 本地打包的 Python 依赖（含 `bplib`, `petlib` 等），无需全局安装。 |

## Dependencies and Environment / 依赖与环境

- Python 3.12（see `11-15/lib/python3.12/site-packages`）。
- Third-party libraries：`cryptography`, `bplib`, `petlib`, `pycryptodome`（included in the project）。

Before running the scripts, you can add the built-in site-packages to your environment variable: / 运行脚本前，可将内置 site-packages 加入环境变量：

```bash
export PYTHONPATH="$(pwd)/11-15/lib/python3.12/site-packages:$PYTHONPATH"
```

## Core Process Overview / 核心流程概述

1. **Public Parameter Initialization**: `bplib.bp.BpGroup()` provides a BN curve and generators. / **公共参数初始化**：`bplib.bp.BpGroup()` 提供 BN 曲线及生成元。
2. **Double Ratchet / Key Agreement**: `trade.py` uses `DoubleRatchet` to generate sending/receiving chain keys; `fresh+AE.py` and `naive.py` respectively maintain or re-establish DH agreements. / **双棘轮/密钥协商**：`trade.py` 使用 `DoubleRatchet` 生成发送/接收链密钥；`fresh+AE.py` 与 `naive.py` 分别保持或重建 DH 协商。
3. **Data Protection**: The data key is used to encrypt 500 MB of random data via AES-CBC, and the data key itself is protected layer by layer using AES-GCM + PRE to enable entrusted decryption. / **数据保护**：数据密钥通过 AES-CBC 加密 500MB 随机数据，数据密钥自身用 AES-GCM + PRE 层层保护，实现可委托解密。
4. **Keyword Search**: `peks.py` handles keyword blind signing and searchable ciphertext generation; the exchange performs keyword matching. / **关键词搜索**：`peks.py` 负责关键词盲签名与可搜索密文生成，交易所对关键词进行匹配。
5. **Proxy Re-Encryption**: The broker applies PRE to the stored key ciphertext so that the buyer can decrypt it with their own key. / **代理重加密**：经纪人对存储的密钥密文应用 PRE，使买家凭自身密钥解密。

## Usage / 使用方法

### Run the Main Experiment / 运行主实验

By default, 500 MB of random data is generated. For the first run, please ensure sufficient memory/disk space. You can reduce the value in `data.generate(1024 * 1024 * 500)` for faster debugging. / 默认会生成 500MB 随机数据，第一次运行请确保有足够内存/磁盘，并可将 `data.generate(1024 * 1024 * 500)` 改为更小值加快调试。

```bash
python trade.py          # ESECDT
python fresh+AE.py       # fresh + AE
python naive.py          # DH + AE
```

The scripts will print the average time for each phase (delegate / DRcv / retrieve / deliver / BRcv) and the total time, and verify the correctness of decryption. / 脚本会打印各阶段平均耗时（delegate / DRcv / retrieve / deliver / BRcv）与总耗时，并校验解密正确性。

### Generate Random Data / 生成随机数据

```bash
python -c "import data; print(data.generate(32))"
```

This returns a hexadecimal random string of the specified byte length. / 将返回指定字节数的十六进制随机串。

## Notes / 注意事项

- `trade.py`/`fresh+AE.py`/`naive.py` generate three keywords per round by default and loop 20 times. For faster testing, you can reduce the loop count or data size. / `trade.py`/`fresh+AE.py`/`naive.py` 默认每轮生成三条关键词，循环 20 次，如需更快测试可调小循环次数或数据大小。
- AES keys and nonces are generated using `os.urandom`. Do not change them arbitrarily in production. / AES 密钥与随机数均使用 `os.urandom`，不要在生产环境中随意更改。
- In `proxy_re_encrypt_sdk.py`, plaintext is encoded/decoded through large integer operations. If you need to handle binary data, please wrap it accordingly. / `proxy_re_encrypt_sdk.py` 中的明文通过大整数运算编码/解码，如需二进制数据请自行封装。
- Currently, there are no automated tests. If you want to integrate CI, you can encapsulate the main process as functions and write `pytest`/`unittest` scripts. / 目前无自动化测试，若要集成 CI，可将主要流程封装为函数并编写 `pytest`/`unittest`。
