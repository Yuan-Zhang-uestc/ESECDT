# Subscripton-Based Entrust Delivery Experimental Framework

This project implements an end-to-end encrypted data delivery process ESECDT leveraging public-key encryption with keyword search (PEKS), proxy re-encryption (PRE), and double ratchet key agreement (DR). It is used ri evaluate the performance of different key management strategies (`trade.py`, `fresh+AE.py`, `naive.py`) in large data transmission scenarios.

## Directory

| File | Description |
| --- | --- |
| `trade.py` | Main experiment script for ESECDT, containg the seller, broker, and buyer workflows and timing statistics. |
| `fresh+AE.py` | Scheme with a persistent shared key + data key re-encryption using authenticated encryption (AE). |
| `naive.py` | A baseline scheme that renegotiates a Diffie-Hellman key in each round. |
| `proxy_re_encrypt_sdk.py` | PRE SDK: key generation, re-encryption key generation, two types of encryption/decryption processes. |
| `peks.py` | PEKS toolkit: keyword hashing, signing, trapdoor construction, etc. |
| `data.py` | Random data generation, by default producing a hexadecimal string of specified length. |
| `verify_curve_points.py` | Script to verify the length of elliptic curve points, sampling multiple rounds to confirm the encoding length of G1/G2 points. |
| `curve_point_verification.md` | Records the steps and outputs of elliptic curve point verification. |
| `11-15/` | Locally packaged Python dependencies (including bplib, petlib, etc.), no global installation required. |

## Dependencies and Environment

- Python 3.12（see `11-15/lib/python3.12/site-packages`）。
- Third-party libraries：`cryptography`, `bplib`, `petlib`, `pycryptodome`（included in the project）。

Before running the scripts, you can add the built-in site-packages to your environment variable：

```bash
export PYTHONPATH="$(pwd)/11-15/lib/python3.12/site-packages:$PYTHONPATH"
```

## Core Process Overview

1. **Public Parameter Initialization**: `bplib.bp.BpGroup()` provides a BN curve and generators.
2. **Double Ratchet / Key Agreement**: `trade.py` uses `DoubleRatchet` to generate sending/receiving chain keys; `fresh+AE.py` and `naive.py` respectively maintain or re-establish DH agreements.
3. **Data Protection**: The data key is used to encrypt 500 MB of random data via AES-CBC, and the data key itself is protected layer by layer using AES-GCM + PRE to enable entrusted decryption.
4. **Keyword Search**: `peks.py` handles keyword blind signing and searchable ciphertext generation; the exchange performs keyword matching.
5. **Proxy Re-Encryption**: The broker applies PRE to the stored key ciphertext so that the buyer can decrypt it with their own key.

## Usage

### Run the Main Experiment

By default, 500 MB of random data is generated. For the first run, please ensure sufficient memory/disk space. You can reduce the value in `data.generate(1024 * 1024 * 500)` for faster debugging.

```bash
python trade.py          # ESECDT
python fresh+AE.py       # fresh + AE
python naive.py          # DH + AE
```

The scripts will print the average time for each phase (delegate / DRcv / retrieve / deliver / BRcv) and the total time, and verify the correctness of decryption.

### Generate Random Data

```bash
python -c "import data; print(data.generate(32))"
```

This returns a hexadecimal random string of the specified byte length.

## Notes

- `trade.py`/`fresh+AE.py`/`naive.py` generate three keywords per round by default and loop 20 times. For faster testing, you can reduce the loop count or data size.
- AES keys and nonces are generated using `os.urandom`. Do not change them arbitrarily in production.
- In `proxy_re_encrypt_sdk.py`, plaintext is encoded/decoded through large integer operations. If you need to handle binary data, please wrap it accordingly.
- Currently, there are no automated tests. If you want to integrate CI, you can encapsulate the main process as functions and write `pytest`/`unittest` scripts.
