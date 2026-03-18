# SignSeal

A file encryption and digital signature suite with a command-line interface (CLI) and a graphical user interface (GUI), and Python API. It uses modern cryptographic primitives and supports encrypted files, encrypted folders, and optional sender signatures.

## **WARNING**: USE AT YOUR OWN RISK

This application was developed as part of an agentic coding exercise involving multiple frontier AI models. It uses the Python cryptography library with widely trusted cryptographic primitives, so the encrypted output is generally considered secure when correctly implemented and used. However, security during runtime (while the application is open) is not guaranteed. Sensitive data may be exposed during operation due to implementation flaws, improper usage, or active exploitation by malicious actors.

Despite multiple development and review passes, this software has not undergone formal security auditing. No guarantee is made regarding the confidentiality, integrity, or availability of data processed by this software. Use of this software is at your own risk.

## Features & Specifications

- Supports files and folders up to 100 GB total.
- **Authenticated Encryption**: AES-256-GCM for confidentiality and integrity.
- **Optional Digital Signatures**: Ed25519 for sender signing and verification.
- **Key Agreement**: X448 (Curve448) for recipient key exchange.
- **Key Protection**: Argon2id KDF for protecting private keys.
- **Key Derivation**: HKDF-SHA-512 for session keys.
- **Compression**: Zstandard (zstd) transparent compression before encryption.
- **Vault System**: Encrypted key storage for managing encrypt, decrypt, sign, and verify keys.

## Installation

API-only install:

```bash
pip install -e .[api]
```

GUI dependencies:

```bash
pip install -e .[gui]
```

Build tooling:

```bash
pip install -e .[build]
```

Everything:

```bash
pip install -e .[full]
```

## Usage (GUI)

For graphical interface, launch `gui` (or `python -m SignSeal.gui`).

### Vault Management

When you start the GUI, you will be prompted to either **Open** an existing vault or create a **New** one. 

- **New Vault**: Prompts for a save location and a master password.
- **Open Vault**: Prompts for the vault file and its master password.
- **Empty Vault State**: If a vault has no keys, the application presents a simplified "Welcome" view with only **Generate Keys** and **Import Keys** options.

### Secure Workspace

You can encrypt and decrypt files and folders once you have keys in your vault.

1.  Click **Browse...** to select a file or folder.
2.  Under **Recipient:**, choose a recipient key to use to encrypt or decrypt.
3.  Under **Sender:**, choose a sender key to sign during encryption or verify during decryption.
4.  Type the password for the decryption or signing key.
5.  Click **Encrypt** or **Decrypt**.

## Usage (CLI)

The CLI can be run using `cli` (if installed) or `python -m SignSeal.cli`. 

### Vault vs. Standalone Mode

The CLI supports two modes of operation:
1. **Vault Mode**: Use `-v/--vault` with a vault name (e.g., `Bob`) to use keys stored in your encrypted vault.
2. **Standalone Mode**: Omit `-v` and provide paths to key files directly (e.g., `./public_encrypt.key`).

### Key Management (Vault)

*   **Initialize**: `cli init -v my_vault.db [--replace]`
*   **List**: `cli list -v my_vault.db`
*   **Generate**: `cli generate "MyKey" -v my_vault.db [--security low|medium|high]`
*   **Import**: `cli import "FriendName" ./path/to/keys -v my_vault.db`
*   **Export**: `cli export "MyKey" ./output -v my_vault.db`
*   **Remove**: `cli remove "FriendName" -v my_vault.db`
*   **Rename**: `cli rename "OldName" "NewName" -v my_vault.db`
*   **Show**: `cli show "MyKey" -v my_vault.db [--paper]`
*   **Add**: `cli add "MyKey" <alphanumeric_string_or_file> -v my_vault.db`
*   **Change Password**: `cli password -v my_vault.db`

### Encryption & Decryption

#### Vault Mode
```bash
# Encrypt using vault entry names
cli encrypt -v my_keys.db my_data.txt -r Bob -s Alice [-z/--compress]

# Decrypt using vault entry names
cli decrypt -v my_keys.db my_data.txt.ssv1 -r Bob -s Alice [--replace]
```

#### Standalone Mode
```bash
# Encrypt using file paths
cli encrypt my_data.txt -r public_encrypt.key -s private_sign.key

# Decrypt using file paths
cli decrypt my_data.txt.ssv1 -r private_decrypt.key -s public_verify.key
```

### Detached Signatures

```bash
# Create a detached signature
cli sign -v my.db document.pdf -s Alice

# Verify a detached signature
cli verify -v my.db document.pdf -s Alice --signature document.pdf.sig
```

### Miscellaneous

*   **Fingerprint**: `cli fingerprint public_encrypt.key`
*   **Generate to Disk**: `cli generate [output_dir] [--security low|medium|high] [--force]`

## Usage (Python API)

The `SignSeal` package is directly callable and provides a unified interface for both standalone and vault-backed operations.

### Basic Initialization

```python
import SignSeal

# 1. Standalone mode (for operations with individual key files)
ss = SignSeal()

# 2. Vault mode (for operations using keys stored in a vault)
ss = SignSeal("vault-password", "my_keys.db")
```

### Core Operations

```python
# Encrypt a file, folder, or bytes
# In standalone mode, keys are paths to files or bytes.
# In vault mode, keys are entry names.
ss.encrypt(
    "message.txt",
    recipient_key="Bob",  # Entry name or path
    sender_key="Alice",   # Entry name or path
    sender_passphrase="alice-password",
    out="message.txt.ssv1",
    compress=True,
)

# Decrypt a file, folder, or bytes
ss.decrypt(
    "message.txt.ssv1",
    recipient_key="Bob",
    recipient_passphrase="bob-password",
    sender_key="Alice",
    out="message.dec.txt",
)

# Detached Signatures
sig = ss.sign("file.pdf", sender_key="Alice", sender_passphrase="...", out="file.pdf.sig")
fingerprint = ss.verify_detached("file.pdf", "file.pdf.sig", sender_key="Alice")
```

# Vault Management

When using `SignSeal` in vault mode, you can manage your keys programmatically:

```python
# Generate new keys in the vault
ss.generate("entry-password", name="Alice")

# Generate standalone keys into a directory
ss.generate("key-password", output_dir="./my_keys")

# List all entries
entries = ss.list()
```

# Show details and paper keys
print(ss.show("Alice", paper=True))

# Import and Export
ss.import_keys("Friend", "./keys")
ss.export("Alice", "./backups")

# Miscellaneous
ss.note("Alice", "Added a personal note")
ss.rename("Bob", "Robert")
ss.remove("OldKey")
ss.password("new-vault-password")

# Fingerprints and Paper Keys
print(ss.fingerprint("Alice"))
print(ss.paper_keys("Alice"))
```

### Using as a Context Manager

It is recommended to use `SignSeal` as a context manager to ensure the vault is properly closed.

```python
with SignSeal("vault-password", "my_keys.db") as ss:
    ss.encrypt(...)
```


