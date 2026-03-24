# SignSeal

A file encryption and digital signature suite with a command-line interface (CLI) and a graphical user interface (GUI), and Python API. It uses modern cryptographic primitives and supports encrypted files, encrypted folders, and optional sender signatures.

## **WARNING**: USE AT YOUR OWN RISK

This application was developed as part of an agentic coding exercise involving multiple frontier AI models available at the time of creation, including Claude Opus 4.6, GPT-5.4, and Gemini 3.1.

It uses the Python cryptography library with widely trusted cryptographic primitives, so the encrypted output is generally considered secure when correctly implemented and used. However, security during runtime (while the application is open) is not guaranteed. Sensitive data may be exposed during operation due to implementation flaws, improper usage, or active exploitation by malicious actors. This includes potential exposure through memory, temporary storage, logging, or other system-level vulnerabilities.

Despite multiple development and review passes by these models, this software has not undergone formal security auditing. Vulnerabilities may exist, including but not limited to implementation errors, improper key handling, or unintended data exposure during operation. No guarantee is made regarding the confidentiality, integrity, or availability of data processed by this software.

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to warranties of merchantability or fitness for a particular purpose.

## LIMITATION OF LIABILITY

To the fullest extent permitted by applicable law, in no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

This includes, without limitation, any direct, indirect, incidental, special, consequential, or exemplary damages, including but not limited to loss of data, loss of profits, loss of use, or security breaches.

Use of this software is at your own risk.

## Features & Specifications

- Supports files and folders up to 100 GB total.
- **Authenticated Encryption**: AES-256-GCM for confidentiality and integrity.
- **Optional Digital Signatures**: Ed25519 for sender signing and verification.
- **Key Agreement**: X448 (Curve448) for recipient key exchange.
- **Key Protection**: Argon2id KDF for protecting private keys.
- **Key Derivation**: HKDF-SHA-512 for session keys.
- **Compression**: Zstandard (zstd) transparent compression before encryption.
- **Vault System**: Encrypted key storage for managing encrypt, decrypt, sign, and verify keys.

## What Is Asymmetric cryptography

Asymmetric cryptography uses a pair of keys: a public key and a private key. These keys serve different roles depending on how they are used. This application uses four key types:

1. Encryption: A public key used by the sender to encrypt data.
2. Signing: A private key used by the sender to create a digital signature.
3. Decryption: A private key used by the recipient to decrypt data.
4. Verification: A public key used by the recipient to verify a signature.

Public keys are used for encryption and signature verification. This allows anyone to encrypt data for the recipient, and anyone with the sender’s public key to verify that a message was created by the holder of the corresponding private key and has not been altered. Public keys can be freely shared, and there is no security risk if they are exposed to unintended parties.

Private keys are used for decryption and signing. This ensures that only the intended recipient can read the message, and only the holder of the private key can create a valid signature. Private keys must be kept secret and never shared. If they are exposed, you must stop using them, generate new public and private keys, and distribute the new public keys.

In addition, private keys are protected by a password, which is required to unlock and use them.

Consider a scenario where Alice and Bob want to exchange files securely.

### Setup:

1. Alice generates her keys and labels as Alice.
2. Bob generates his keys and labels as Bob.
3. They exchange their public keys with each other.
4. Each person imports the other’s public key and associates it with the correct name.

### Sending a file (Bob to Alice):

1. Bob selects the file to send.
2. He selects Alice as the recipient, so the application uses Alice’s public key to encrypt the file.
3. He selects himself as the sender, so the application uses his private key to sign the file.
4. He enters the password to unlock his private key to sign.
5. He clicks Encrypt.
6. He sends the encrypted file to Alice.

### Receiving a file (Alice from Bob):

1. Alice selects the encrypted file that Bob sent.
2. She selects herself as the recipient, so the application uses her private key to decrypt the file.
3. She selects Bob as the sender, so the application uses Bob’s public key to verify the signature.
4. She enters the password to unlock her private key to decrypt.
5. She clicks Decrypt.
6. She opens the decrypted content.

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
pip install -e .[all]
```

## Usage (GUI)

For the graphical interface, launch `ss-gui`.

### Vault Management

When you start the GUI, you will be prompted to either **Open** an existing vault or create a **New** one. 

- **New Vault**: Prompts for a save location and a master password. Vaults use the `.ssvv0` extension.
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

The CLI is accessible via the `ss-cli` command.

### Vault vs. Standalone Mode

The CLI supports two modes of operation:
1. **Vault Mode**: Use `-v/--vault` with a vault name (e.g., `Bob`) to use keys stored in your encrypted vault.
2. **Standalone Mode**: Omit `-v` and provide paths to key files directly (e.g., `./public_encrypt.sskv0`).

### Key Management (Vault)

*   **Initialize**: `ss-cli init -v my_vault [--replace]`
*   **Generate**: `ss-cli generate "MyKey" -v my_vault [--security low|medium|high]`
*   **Export**: `ss-cli export MyKey ./ -v my_vault`
*   **Import**: `ss-cli import Alice ./MyKey -v my_vault`
*   **Show**: `ss-cli show Alice -v my_vault [--paper]`
*   **Add**: `ss-cli add test paper-keys.txt -v my_vault`
*   **Rename**: `ss-cli rename test Bob -v my_vault`
*   **Remove**: `ss-cli remove MyKey -v my_vault`
*   **List**: `ss-cli list -v my_vault`
*   **Change Password**: `ss-cli password -v my_vault`

### Encryption & Decryption

#### Vault Mode
```bash
# Encrypt using vault entry names
ss-cli encrypt data.txt -r Bob -s Alice -v my_vault [-z/--compress]

# Decrypt using vault entry names
ss-cli decrypt data.txt.ssfv0 -r Bob -s Alice -v my_vault [--replace]
```

### Detached Signatures

```bash
# Create a detached signature
ss-cli sign data.txt -s Alice -v my_vault

# Verify a detached signature
ss-cli verify data.txt -s Alice --signature data.txt.sig -v my_vault
```


#### Standalone Mode
```bash
# Generate to Disk
ss-cli generate key_path # [--security low|medium|high] [--force]

# Fingerprint
ss-cli fingerprint key_path/public_encrypt.sskv0

# Encrypt using file paths
ss-cli encrypt data.txt -r Alice/public_encrypt.sskv0 -s Bob/private_sign.sskv0

# Decrypt using file paths
ss-cli decrypt data.txt.ssfv0 -r Alice/private_decrypt.sskv0 -s Bob/public_verify.sskv0
```

## Usage (Python API)

The `SignSeal` package provides a unified interface for both standalone and vault-backed operations.

### Basic Initialization

```python
import SignSeal

# 1. Standalone mode (for operations with individual key files)
ss = SignSeal()

# 2. Vault mode (for operations using keys stored in a vault)
ss = SignSeal("vault-password", "my_vault.ssvv0")
```

### Core Operations

```python
# Encrypt a file, folder, or bytes
# In standalone mode, keys are paths to files or bytes.
# In vault mode, keys are entry names.
ss.encrypt(
    "data.txt",
    recipient_key="Bob",  # Entry name or path
    sender_key="Alice",   # Entry name or path
    sender_passphrase="alice-password",
    out="data.txt.ssfv0",
    compress=True,
)

# Decrypt a file, folder, or bytes
ss.decrypt(
    "data.txt.ssfv0",
    recipient_key="Bob",
    recipient_passphrase="bob-password",
    sender_key="Alice",
    out="data.dec.txt",
)

# Detached Signatures
sig = ss.sign("file.pdf", sender_key="Alice", sender_passphrase="...", out="file.pdf.sig")
fingerprint = ss.verify_detached("file.pdf", "file.pdf.sig", sender_key="Alice")
```

### Vault Management

When using `SignSeal` in vault mode, you can manage your keys programmatically:

```python
# Generate new keys in the vault
ss.generate("entry-password", name="Alice")

# Generate standalone keys into a directory
ss.generate("key-password", output_dir="./my_keys")

# List all entries
entries = ss.list()

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

# Fingerprints
print(ss.fingerprint("Alice"))
```
