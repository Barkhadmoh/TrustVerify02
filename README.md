# TrustVerify 🔐
A Python CLI tool for file integrity verification and RSA digital signatures.

> Mini Project I — Information Security Course

---

## Team Members
| Name | Student ID |
|------|------------|
| Barkhad Mohamed | 210208908 |

---

## Install
```bash
pip install cryptography
```

## Quick Start
```bash
# 1. Hash a single file
py trustverify.py hash file1.txt

# 2. Generate a manifest for a directory
py trustverify.py manifest .

# 3. Check integrity
py trustverify.py check

# 4. Generate RSA key pair
py trustverify.py keygen

# 5. Sign the manifest
py trustverify.py sign

# 6. Verify signature and integrity
py trustverify.py verify
```

## Demo: Tampering Detection
```bash
# After signing, tamper with a file:
# Open file1.txt and change the text, then save it

# Integrity check catches it:
py trustverify.py verify

# ⚠️  TAMPERED:  file1.txt
# ❌ Signature INVALID
```

## Project Structure
```
TrustVerify/
├── trustverify.py    # Main CLI tool (all 6 tasks)
├── report.md         # 2-page report
├── metadata.json     # Generated manifest
├── public_key.pem    # RSA public key
└── README.md
```
