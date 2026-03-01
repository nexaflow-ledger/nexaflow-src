#!/usr/bin/env python3
"""
Generate validator credentials for a NexaFlow node.

Produces two kinds of artefacts:

1. **BFT consensus keys** (secp256k1)
     - ``certs/<node-id>.key``        — 32-byte hex private key
     - ``certs/pubkeys/<node-id>.pub`` — 65-byte hex uncompressed public key

2. **TLS certificates** (X.509, self-signed CA + node cert)
     - ``certs/ca.key``        — CA private key (PEM)
     - ``certs/ca.crt``        — CA self-signed certificate (PEM)
     - ``certs/<node-id>.key`` — Node TLS private key  (PEM, also contains the
                                  secp256k1 key above so only one file is needed)
     - ``certs/<node-id>.crt`` — Node TLS certificate signed by the CA (PEM)

Usage:
    # Generate CA + a single validator's credentials:
    python scripts/gen_node_cert.py --node-id validator-1

    # Generate credentials for multiple validators (shared CA):
    python scripts/gen_node_cert.py --node-id validator-1
    python scripts/gen_node_cert.py --node-id validator-2 --existing-ca

    # Custom output directory:
    python scripts/gen_node_cert.py --node-id validator-1 --out-dir /etc/nexaflow/certs

After running, update nexaflow.toml:

    [consensus]
    validator_key_file = "certs/validator-1.key"
    validator_pubkeys_dir = "certs/pubkeys/"

    [tls]
    enabled = true
    cert_file = "certs/validator-1.crt"
    key_file  = "certs/validator-1-tls.key"
    ca_file   = "certs/ca.crt"
    verify_peer = true
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so we can import nexaflow_core
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from ecdsa import SECP256k1, SigningKey
except ImportError:
    sys.exit(
        "ERROR: 'ecdsa' package is required.  Install it with:\n"
        "  pip install ecdsa"
    )

# Optional: use cryptography for X.509 cert generation
_HAS_CRYPTOGRAPHY = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    pass


# ===================================================================
#  BFT consensus key generation (secp256k1)
# ===================================================================

def generate_consensus_keys(
    node_id: str, out_dir: Path
) -> tuple[str, str]:
    """
    Generate a secp256k1 key pair for BFT consensus proposal signing.

    Returns (private_key_path, public_key_path).
    """
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    priv_hex = sk.to_string().hex()                     # 32 bytes → 64 hex chars
    pub_hex = b"\x04".hex() + vk.to_string().hex()      # 65 bytes → 130 hex chars

    priv_path = out_dir / f"{node_id}.key"
    pub_dir = out_dir / "pubkeys"
    pub_dir.mkdir(parents=True, exist_ok=True)
    pub_path = pub_dir / f"{node_id}.pub"

    priv_path.write_text(priv_hex + "\n")
    pub_path.write_text(pub_hex + "\n")

    # Restrict permissions on the private key
    os.chmod(priv_path, 0o600)

    return str(priv_path), str(pub_path)


# ===================================================================
#  TLS certificate generation (X.509)
# ===================================================================

def _generate_tls_with_cryptography(
    node_id: str, out_dir: Path, existing_ca: bool
) -> tuple[str, str, str]:
    """Generate TLS certs using the `cryptography` library."""
    ca_key_path = out_dir / "ca.key"
    ca_crt_path = out_dir / "ca.crt"

    if existing_ca and ca_key_path.exists() and ca_crt_path.exists():
        # Load existing CA
        ca_key = serialization.load_pem_private_key(
            ca_key_path.read_bytes(), password=None
        )
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
        print(f"  Using existing CA: {ca_crt_path}")
    else:
        # Generate new CA
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexaFlow Network"),
            x509.NameAttribute(NameOID.COMMON_NAME, "NexaFlow CA"),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        ca_key_path.write_bytes(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(ca_key_path, 0o600)
        ca_crt_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        print(f"  Generated CA: {ca_crt_path}")

    # --- Node certificate ---
    node_key = ec.generate_private_key(ec.SECP256R1())
    node_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexaFlow Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, node_id),
    ])
    node_cert = (
        x509.CertificateBuilder()
        .subject_name(node_name)
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(node_id),
                x509.DNSName("localhost"),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("127.0.0.1")
                ),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    tls_key_path = out_dir / f"{node_id}-tls.key"
    tls_crt_path = out_dir / f"{node_id}.crt"

    tls_key_path.write_bytes(
        node_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(tls_key_path, 0o600)
    tls_crt_path.write_bytes(node_cert.public_bytes(serialization.Encoding.PEM))

    return str(tls_crt_path), str(tls_key_path), str(ca_crt_path)


def _generate_tls_with_openssl(
    node_id: str, out_dir: Path, existing_ca: bool
) -> tuple[str, str, str]:
    """Fallback: generate TLS certs by shelling out to openssl."""
    import subprocess

    ca_key_path = out_dir / "ca.key"
    ca_crt_path = out_dir / "ca.crt"

    def _run(cmd: list[str]) -> None:
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    if not (existing_ca and ca_key_path.exists() and ca_crt_path.exists()):
        # Generate CA key + self-signed cert
        _run([
            "openssl", "ecparam", "-genkey", "-name", "prime256v1",
            "-out", str(ca_key_path),
        ])
        os.chmod(ca_key_path, 0o600)
        _run([
            "openssl", "req", "-new", "-x509",
            "-key", str(ca_key_path),
            "-out", str(ca_crt_path),
            "-days", "3650",
            "-subj", "/O=NexaFlow Network/CN=NexaFlow CA",
        ])
        print(f"  Generated CA: {ca_crt_path}")
    else:
        print(f"  Using existing CA: {ca_crt_path}")

    tls_key_path = out_dir / f"{node_id}-tls.key"
    tls_csr_path = out_dir / f"{node_id}.csr"
    tls_crt_path = out_dir / f"{node_id}.crt"

    # Node key
    _run([
        "openssl", "ecparam", "-genkey", "-name", "prime256v1",
        "-out", str(tls_key_path),
    ])
    os.chmod(tls_key_path, 0o600)

    # CSR
    _run([
        "openssl", "req", "-new",
        "-key", str(tls_key_path),
        "-out", str(tls_csr_path),
        "-subj", f"/O=NexaFlow Network/CN={node_id}",
    ])

    # Sign with CA
    ext_file = out_dir / f"{node_id}-ext.cnf"
    ext_file.write_text(
        f"subjectAltName=DNS:{node_id},DNS:localhost,IP:127.0.0.1\n"
    )
    _run([
        "openssl", "x509", "-req",
        "-in", str(tls_csr_path),
        "-CA", str(ca_crt_path),
        "-CAkey", str(ca_key_path),
        "-CAcreateserial",
        "-out", str(tls_crt_path),
        "-days", "365",
        "-extfile", str(ext_file),
    ])

    # Clean up temp files
    tls_csr_path.unlink(missing_ok=True)
    ext_file.unlink(missing_ok=True)
    (out_dir / "ca.srl").unlink(missing_ok=True)

    return str(tls_crt_path), str(tls_key_path), str(ca_crt_path)


def generate_tls_certs(
    node_id: str, out_dir: Path, existing_ca: bool = False
) -> tuple[str, str, str]:
    """
    Generate TLS CA + node certificate.

    Uses the ``cryptography`` library if available, otherwise falls
    back to shelling out to ``openssl``.

    Returns (cert_path, key_path, ca_path).
    """
    if _HAS_CRYPTOGRAPHY:
        return _generate_tls_with_cryptography(node_id, out_dir, existing_ca)
    else:
        return _generate_tls_with_openssl(node_id, out_dir, existing_ca)


# ===================================================================
#  Main
# ===================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate NexaFlow validator credentials (BFT keys + TLS certs)."
    )
    parser.add_argument(
        "--node-id", required=True,
        help="Unique validator identifier (e.g. validator-1)",
    )
    parser.add_argument(
        "--out-dir", default="certs",
        help="Output directory for keys and certificates (default: certs/)",
    )
    parser.add_argument(
        "--existing-ca", action="store_true",
        help="Reuse an existing CA (ca.key + ca.crt) in --out-dir instead "
             "of generating a new one",
    )
    parser.add_argument(
        "--skip-tls", action="store_true",
        help="Only generate BFT consensus keys, skip TLS certificates",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n── Generating credentials for {args.node_id} ──\n")

    # 1. BFT consensus keys
    priv_path, pub_path = generate_consensus_keys(args.node_id, out_dir)
    print(f"  BFT private key:  {priv_path}")
    print(f"  BFT public key:   {pub_path}")

    # 2. TLS certificates
    if not args.skip_tls:
        try:
            cert_path, key_path, ca_path = generate_tls_certs(
                args.node_id, out_dir, args.existing_ca
            )
            print(f"  TLS certificate:  {cert_path}")
            print(f"  TLS private key:  {key_path}")
            print(f"  TLS CA cert:      {ca_path}")
        except Exception as e:
            print(f"\n  ⚠ TLS generation failed: {e}")
            print("    Install 'cryptography' or ensure 'openssl' is on PATH.")
            print("    BFT consensus keys were still created successfully.\n")
            _print_config_snippet(args.node_id, priv_path, pub_path)
            return

    # 3. Print config snippet
    print()
    _print_config_snippet(
        args.node_id, priv_path, pub_path,
        cert_path if not args.skip_tls else None,
        key_path if not args.skip_tls else None,
        ca_path if not args.skip_tls else None,
    )


def _print_config_snippet(
    node_id: str,
    priv_path: str,
    pub_path: str,
    cert_path: str | None = None,
    key_path: str | None = None,
    ca_path: str | None = None,
) -> None:
    pub_dir = str(Path(pub_path).parent)
    print("── Add to nexaflow.toml ──────────────────────────────────\n")
    print('[consensus]')
    print(f'validator_key_file = "{priv_path}"')
    print(f'validator_pubkeys_dir = "{pub_dir}/"')
    if cert_path:
        print()
        print('[tls]')
        print('enabled = true')
        print(f'cert_file = "{cert_path}"')
        print(f'key_file  = "{key_path}"')
        print(f'ca_file   = "{ca_path}"')
        print('verify_peer = true')
    print()
    print("── Share with other validators ───────────────────────────\n")
    print(f"  Copy {pub_path}")
    print("  into each peer's pubkeys/ directory so they can verify")
    print("  this node's consensus proposals.\n")
    if ca_path:
        print(f"  Also distribute {ca_path} to all peers for mutual TLS.\n")


if __name__ == "__main__":
    main()
