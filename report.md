# TrustVerify – Project Report

**Course:** Security / Cryptography Mini Project 1  
**Tool:** TrustVerify – CLI for File Integrity & Digital Signatures

---

## 1. Why Hashing Alone Is Not Enough to Prove Identity

A SHA-256 hash proves that a file's content has not changed — 
this is called integrity. If you hash a file today and hash it 
again tomorrow and the values match, you know no one modified 
the bytes in between.

However, hashing alone says nothing about who created the file. 
Anyone can:

1. Download a file
2. Modify it
3. Recompute a new SHA-256 hash of the modified version
4. Send both the modified file and the new hash to the receiver

The receiver will compare the file against the new hash, the 
values will match, and they will have no way of knowing the file 
was tampered with — because the hash was also replaced by the 
attacker.

This is why hashing provides integrity but not authenticity. 
To prove that a specific person created and signed the data, 
we need digital signatures.

---

## 2. How Public/Private Key Pairs Ensure Non-Repudiation

RSA digital signatures work on a mathematical asymmetry:

- The private key can sign data. Only the sender owns this.
- The public key can verify that signature. Anyone can have this.

### Signing Process (Sender)
1. The sender computes the SHA-256 hash of metadata.json
2. They encrypt that hash with their private key to produce the signature
3. They send the file, manifest, and signature to the receiver

### Verification Process (Receiver)
1. The receiver recomputes the SHA-256 hash of the received metadata.json
2. They decrypt the signature using the sender's public key
3. If both hashes match, the manifest is verified as authentic and unmodified

### Why This Ensures Non-Repudiation
- Only the sender holds the private key, so only they could have 
  produced that signature
- If the manifest is altered after signing, the hashes will not 
  match and verification fails
- The sender cannot deny having signed the manifest, because the 
  public key mathematically confirms the signature came from the 
  private key

This combination of SHA-256 hashing and RSA signatures gives us 
both integrity (the file was not changed) and authenticity 
(the file came from the claimed sender).

---

## How to Run the Tool

### Install dependency
pip install cryptography

### Commands
- py trustverify.py hash myfile.txt      — Hash a single file
- py trustverify.py manifest .           — Create manifest
- py trustverify.py check                — Check for tampering
- py trustverify.py keygen               — Generate RSA keys
- py trustverify.py sign                 — Sign the manifest
- py trustverify.py verify               — Verify signature and integrity