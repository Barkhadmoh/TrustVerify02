"""
TrustVerify - A CLI tool for File Integrity and Digital Signatures
Usage: python trustverify.py [command] [options]
"""

import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# PART 1 – HASHING AND LOCAL INTEGRITY
# ─────────────────────────────────────────────

def hash_file(filepath):
    """Task 1: Return the SHA-256 hash of a single file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_manifest(directory="."):
    """
    Task 2: Scan a directory and create metadata.json
    containing each filename and its SHA-256 hash.
    Skips metadata.json itself to avoid circular hashing.
    """
    directory = Path(directory)
    manifest = {}

    for file in sorted(directory.iterdir()):
        if file.is_file() and file.name not in ("metadata.json", "signature.bin"):
            manifest[file.name] = hash_file(file)
            print(f"  Hashed: {file.name}")

    output_path = directory / "metadata.json"
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n✅ Manifest saved to: {output_path}")
    return manifest


def check_integrity(directory="."):
    """
    Task 3: Compare current file hashes against metadata.json.
    Reports any added, removed, or tampered files.
    """
    directory = Path(directory)
    manifest_path = directory / "metadata.json"

    if not manifest_path.exists():
        print("❌ metadata.json not found. Run 'manifest' first.")
        return

    with open(manifest_path, "r") as f:
        saved_manifest = json.load(f)

    current_files = {
        f.name: hash_file(f)
        for f in directory.iterdir()
        if f.is_file() and f.name not in ("metadata.json", "signature.bin")
    }

    all_good = True

    for filename, saved_hash in saved_manifest.items():
        if filename not in current_files:
            print(f"  ❌ MISSING:   {filename}")
            all_good = False
        elif current_files[filename] != saved_hash:
            print(f"  ⚠️  TAMPERED:  {filename}")
            all_good = False
        else:
            print(f"  ✅ OK:        {filename}")

    for filename in current_files:
        if filename not in saved_manifest:
            print(f"  ➕ NEW FILE:  {filename} (not in original manifest)")
            all_good = False

    if all_good:
        print("\n✅ All files are intact. No tampering detected.")
    else:
        print("\n⚠️  Integrity check FAILED. Some files were modified or missing.")


# ─────────────────────────────────────────────
# PART 2 – DIGITAL SIGNATURES (RSA)
# ─────────────────────────────────────────────

def generate_keys():
    """
    Task 4: Generate an RSA 2048-bit public/private key pair
    and save them as private_key.pem and public_key.pem.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key (keep this secret!)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key (share this with the receiver)
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ Keys generated:")
    print("   private_key.pem  ← Keep this secret (Sender only)")
    print("   public_key.pem   ← Share this with the Receiver")


def sign_manifest(manifest_path="metadata.json", private_key_path="private_key.pem"):
    """
    Task 5: Hash the metadata.json file and sign the hash
    with the private key. Save signature to signature.bin.
    """
    if not Path(manifest_path).exists():
        print(f"❌ {manifest_path} not found. Run 'manifest' first.")
        return
    if not Path(private_key_path).exists():
        print(f"❌ {private_key_path} not found. Run 'keygen' first.")
        return

    # Step 1: Hash the manifest file
    manifest_hash = hash_file(manifest_path)
    print(f"   Manifest SHA-256: {manifest_hash}")

    # Step 2: Load the private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Step 3: Sign the hash bytes using RSA + PSS padding + SHA-256
    signature = private_key.sign(
        manifest_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Step 4: Save signature
    with open("signature.bin", "wb") as f:
        f.write(signature)

    print("✅ Signature saved to: signature.bin")


def verify_manifest(
    manifest_path="metadata.json",
    signature_path="signature.bin",
    public_key_path="public_key.pem"
):
    """
    Task 6: Verify the manifest's signature using the sender's public key.
    Also runs a full file integrity check.
    """
    for path in [manifest_path, signature_path, public_key_path]:
        if not Path(path).exists():
            print(f"❌ File not found: {path}")
            return

    # Step 1: Recompute the manifest hash
    manifest_hash = hash_file(manifest_path)
    print(f"   Manifest SHA-256: {manifest_hash}")

    # Step 2: Load public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

    # Step 3: Load the signature
    with open(signature_path, "rb") as f:
        signature = f.read()

    # Step 4: Verify the signature
    try:
        public_key.verify(
            signature,
            manifest_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n✅ Signature is VALID.")
        print("   The manifest was signed by the owner of this public key.")
        print("   Now checking file integrity...\n")
        check_integrity(".")
    except Exception:
        print("\n❌ Signature INVALID!")
        print("   The manifest may have been tampered with,")
        print("   or it was not signed by the expected sender.")


# ─────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────

def print_help():
    print("""
TrustVerify – File Integrity & Digital Signature Tool
======================================================

Commands:
  hash <file>         Show SHA-256 hash of a single file
  manifest [dir]      Scan directory and create metadata.json (default: current dir)
  check    [dir]      Check files against metadata.json for tampering
  keygen              Generate RSA public/private key pair
  sign                Sign the metadata.json using private_key.pem
  verify              Verify metadata.json using signature.bin + public_key.pem

Examples:
  python trustverify.py hash myfile.txt
  python trustverify.py manifest ./myfiles
  python trustverify.py check
  python trustverify.py keygen
  python trustverify.py sign
  python trustverify.py verify
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "hash":
        if len(sys.argv) < 3:
            print("Usage: python trustverify.py hash <filepath>")
        else:
            filepath = sys.argv[2]
            if not Path(filepath).exists():
                print(f"❌ File not found: {filepath}")
            else:
                result = hash_file(filepath)
                print(f"SHA-256 of '{filepath}':\n  {result}")

    elif command == "manifest":
        directory = sys.argv[2] if len(sys.argv) > 2 else "."
        print(f"📂 Scanning directory: {directory}\n")
        generate_manifest(directory)

    elif command == "check":
        directory = sys.argv[2] if len(sys.argv) > 2 else "."
        print(f"🔍 Checking integrity in: {directory}\n")
        check_integrity(directory)

    elif command == "keygen":
        print("🔑 Generating RSA key pair...\n")
        generate_keys()

    elif command == "sign":
        print("✍️  Signing manifest...\n")
        sign_manifest()

    elif command == "verify":
        print("🔎 Verifying manifest signature...\n")
        verify_manifest()

    else:
        print(f"❌ Unknown command: '{command}'")
        print_help()