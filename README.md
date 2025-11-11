# 加密交易与可搜索代理重加密实验框架

该项目实现了一个结合 **PEKS（Public-key Encryption with Keyword Search）**、**代理重加密（PRE）** 与 **双棘轮密钥协商** 的端到端加密数据交易流程，用于评估不同密钥管理策略（`trade.py`、`fresh+AE.py`、`naive.py`）在大数据传输场景下的性能。

## 目录结构

| 文件 | 说明 |
| --- | --- |
| `trade.py` | 双棘轮（Double Ratchet）+ PRE + PEKS 的主实验脚本。含卖家、经纪人、买家三方流程及耗时统计。 |
| `fresh+AE.py` | 持久共享密钥 + 数据密钥再次加密（Authenticated Encryption）方案。 |
| `naive.py` | 每轮重新 Diffie-Hellman 协商的朴素方案，作为对照。 |
| `proxy_re_encrypt_sdk.py` | PRE SDK：含密钥生成、重加密密钥生成、两种加/解密流程。 |
| `peks.py` | PEKS 工具集：关键词哈希、签名、Trapdoor 构造等。 |
| `data.py` | 随机数据生成，默认产生指定位数的十六进制串。 |
| `verify_curve_points.py` | 曲线点长度验证脚本，多轮抽样确认 G1/G2 点的编码长度。 |
| `curve_point_verification.md` | 记录椭圆曲线点验证步骤及输出。 |
| `11-15/` | 本地打包的 Python 依赖（含 `bplib`, `petlib` 等），无需全局安装。 |

## 依赖与环境

- Python 3.12（见 `11-15/lib/python3.12/site-packages`）。
- 第三方库：`cryptography`, `bplib`, `petlib`, `pycryptodome`（项目已内置）。

运行脚本前，可将内置 site-packages 加入环境变量：

```bash
export PYTHONPATH="$(pwd)/11-15/lib/python3.12/site-packages:$PYTHONPATH"
```

## 核心流程概述

1. **公共参数初始化**：`bplib.bp.BpGroup()` 提供 BN 曲线及生成元。
2. **双棘轮/密钥协商**：`trade.py` 使用 `DoubleRatchet` 生成发送/接收链密钥；`fresh+AE.py` 与 `naive.py` 分别保持或重建 DH 协商。
3. **数据保护**：数据密钥通过 AES-CBC 加密 500MB 随机数据，数据密钥自身用 AES-GCM + PRE 层层保护，实现可委托解密。
4. **关键词搜索**：`peks.py` 负责关键词盲签名与可搜索密文生成，交易所对关键词进行匹配。
5. **代理重加密**：经纪人对存储的密钥密文应用 PRE，使买家凭自身密钥解密。

## 使用方法

### 运行主实验

默认会生成 500MB 随机数据，第一次运行请确保有足够内存/磁盘，并可将 `data.generate(1024 * 1024 * 500)` 改为更小值加快调试。

```bash
python trade.py          # 双棘轮方案
python fresh+AE.py       # 固定共享密钥 + AE 方案
python naive.py          # 逐轮协商方案
```

脚本会打印各阶段平均耗时（delegate / DRcv / retrieve / deliver / BRcv）与总耗时，并校验解密正确性。

### 生成随机数据

```bash
python -c "import data; print(data.generate(32))"
```

将返回指定字节数的十六进制随机串。

## 注意事项

- `trade.py`/`fresh+AE.py`/`naive.py` 默认每轮生成三条关键词，循环 20 次，如需更快测试可调小循环次数或数据大小。
- AES 密钥与随机数均使用 `os.urandom`，不要在生产环境中随意更改。
- `proxy_re_encrypt_sdk.py` 中的明文通过大整数运算编码/解码，如需二进制数据请自行封装。
- 目前无自动化测试，若要集成 CI，可将主要流程封装为函数并编写 `pytest`/`unittest`。