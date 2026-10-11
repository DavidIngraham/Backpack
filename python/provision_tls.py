#!/usr/bin/env python3
"""Create a Backpack TLS bundle, browser connection URL and Apple CA profile.

Requires Python 3.10+ and OpenSSL 1.1.1+. Private keys stay in the output/CA folders.
Only the device bundle is uploaded; the CA private key never leaves the computer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import subprocess
import uuid


def openssl(*args, binary=False):
    result = subprocess.run(["openssl", *map(str, args)], capture_output=True, check=False)
    if result.returncode:
        # Do not echo command arguments or input bundles containing credentials.
        raise ValueError("OpenSSL operation failed: " + result.stderr.decode(errors="replace")[:600])
    return result.stdout if binary else result.stdout.decode()


def validate_names(hostname, origin):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.local", hostname):
        raise ValueError("Hostname must be one lowercase DNS label followed by .local")
    match = re.fullmatch(r"https://([a-z0-9-]+(?:\.[a-z0-9-]+)*)(?::([0-9]{1,5}))?", origin)
    if not match or (match[2] and not 1 <= int(match[2]) <= 65535) or len(origin) > 192:
        raise ValueError("Origin must be an exact HTTPS origin, without a path or trailing slash")


def apple_profile(ca_pem, hostname):
    import ssl
    der = ssl.PEM_cert_to_DER_cert(ca_pem)
    identifier = "org.expresslrs.backpack." + str(uuid.uuid4())
    return plistlib.dumps({
        "PayloadType": "Configuration", "PayloadVersion": 1,
        "PayloadIdentifier": identifier, "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "Backpack TLS trust: " + hostname,
        "PayloadDescription": "Installs your personal Backpack CA. Enable full trust in Certificate Trust Settings.",
        "PayloadContent": [{
            "PayloadType": "com.apple.security.root", "PayloadVersion": 1,
            "PayloadIdentifier": identifier + ".root", "PayloadUUID": str(uuid.uuid4()),
            "PayloadDisplayName": "Personal Backpack CA", "PayloadContent": der,
        }],
    })


def create_bundle(output, hostname, origin, ca_dir=None, cert=None, key=None, ca_cert=None):
    validate_names(hostname, origin)
    if bool(cert) != bool(key):
        raise ValueError("Provide both --cert and --key")
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if not cert:
        ca_dir = Path(ca_dir) if ca_dir else output / "ca"
        ca_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        ca_key, ca_cert = ca_dir / "ca-key.pem", ca_dir / "ca-cert.pem"
        if ca_key.exists() != ca_cert.exists():
            raise ValueError("CA folder must contain both ca-key.pem and ca-cert.pem, or neither")
        if not ca_key.exists():
            openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
            openssl("req", "-new", "-x509", "-sha256", "-key", ca_key, "-days", "3650",
                    "-subj", "/CN=Personal ELRS Backpack CA " + secrets.token_hex(4), "-out", ca_cert,
                    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        key, cert = output / "device-key.pem", output / "device-cert.pem"
        csr, extensions = output / "device.csr", output / "server.ext"
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        openssl("req", "-new", "-sha256", "-key", key, "-subj", "/CN=" + hostname, "-out", csr)
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:" + hostname + ",IP:10.0.0.1\n")
        openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                "-set_serial", "0x" + secrets.token_hex(16), "-days", "365", "-sha256",
                "-extfile", extensions, "-out", cert)
    certificate = Path(cert).read_text()
    private_key = Path(key).read_text()
    if "ENCRYPTED" in private_key:
        raise ValueError("The device requires an unencrypted PEM private key")
    if len(certificate) > 4096 or len(private_key) > 2048:
        raise ValueError("Certificate chain or private key exceeds firmware limits")
    cert_pub = openssl("x509", "-in", cert, "-pubkey", "-noout")
    key_pub = openssl("pkey", "-in", key, "-pubout", "-passin", "pass:")
    if cert_pub != key_pub:
        raise ValueError("Certificate and private key do not match")
    san = openssl("x509", "-in", cert, "-noout", "-ext", "subjectAltName")
    if "DNS:" + hostname not in [part.strip() for part in san.replace("\n", ",").split(",")]:
        raise ValueError("Certificate SAN must include the exact configured hostname")
    openssl("x509", "-in", cert, "-checkend", "0", "-noout")
    if ca_cert:
        if "CA:TRUE" not in openssl("x509", "-in", ca_cert, "-noout", "-ext", "basicConstraints"):
            raise ValueError("The trust profile requires a CA certificate, not the server leaf")
        openssl("verify", "-CAfile", ca_cert, "-purpose", "sslserver", "-verify_hostname", hostname, cert)
        root = Path(ca_cert).read_text()
        (output / "trust-ca.pem").write_text(root)
        (output / "backpack.mobileconfig").write_bytes(apple_profile(root, hostname))
    token = secrets.token_hex(32)
    bundle = {"version": 1, "hostname": hostname, "origin": origin, "token": token,
              "certificate": certificate, "private_key": private_key}
    encoded = json.dumps(bundle, indent=2).encode()
    if len(encoded) > 8192:
        raise ValueError("TLS bundle exceeds the 8192-byte firmware limit")
    (output / "backpack-tls.json").write_bytes(encoded)
    (output / "connection.txt").write_text(f"wss://{hostname}/mavlink/ws?token={token}\n")
    if "IP Address:10.0.0.1" in san:
        (output / "connection-ap.txt").write_text(f"wss://10.0.0.1/mavlink/ws?token={token}\n")
    der = openssl("x509", "-in", cert, "-outform", "DER", binary=True)
    (output / "certificate-info.txt").write_text(
        "Hostname: " + hostname + "\nPWA origin: " + origin + "\nSHA-256: " + hashlib.sha256(der).hexdigest() + "\n" +
        openssl("x509", "-in", cert, "-noout", "-dates"))
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New private output directory")
    parser.add_argument("--hostname", default="elrs-backpack-" + secrets.token_hex(3) + ".local")
    parser.add_argument("--origin", default="https://gcs.loftedaero.com")
    parser.add_argument("--ca-dir", type=Path, help="Reuse a personal CA for renewal or another Backpack")
    parser.add_argument("--cert", type=Path, help="Import an existing PEM server certificate/chain")
    parser.add_argument("--key", type=Path, help="Import its unencrypted PEM private key")
    parser.add_argument("--ca-cert", type=Path, help="CA PEM for an imported certificate and Apple profile")
    args = parser.parse_args()
    old_umask = os.umask(0o077)
    try:
        create_bundle(args.out, args.hostname, args.origin, args.ca_dir, args.cert, args.key, args.ca_cert)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    finally:
        os.umask(old_umask)
    print("Created TLS provisioning files in", args.out)
    print("Upload backpack-tls.json to the Backpack. Install backpack.mobileconfig on iPad (if generated).")
    print("Enable full trust for your CA, then paste connection.txt into the GCS WebSocket settings.")


if __name__ == "__main__":
    main()
