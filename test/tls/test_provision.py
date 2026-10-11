import importlib.util
from pathlib import Path
import json
import plistlib
import socket
import ssl
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location("provision", Path(__file__).resolve().parents[2] / "python/provision_tls.py")
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class ProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.device = cls.root / "device"
        cls.bundle = provision.create_bundle(cls.device, "elrs-test.local", "https://gcs.loftedaero.com")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_profile_contains_only_public_root(self):
        profile = plistlib.loads((self.device / "backpack.mobileconfig").read_bytes())
        payload = profile["PayloadContent"][0]
        self.assertEqual(payload["PayloadType"], "com.apple.security.root")
        self.assertEqual(payload["PayloadContent"], ssl.PEM_cert_to_DER_cert((self.device / "trust-ca.pem").read_text()))
        self.assertNotIn("PRIVATE", str(profile))
        self.assertEqual(len(self.bundle["token"]), 64)
        self.assertLessEqual((self.device / "backpack-tls.json").stat().st_size, 8192)

    def test_renewal_reuses_ca_and_rotates_device_key(self):
        other = self.root / "renewed"
        renewed = provision.create_bundle(other, "elrs-test.local", "https://gcs.loftedaero.com", self.device / "ca")
        self.assertEqual((other / "trust-ca.pem").read_bytes(), (self.device / "trust-ca.pem").read_bytes())
        self.assertNotEqual(renewed["private_key"], self.bundle["private_key"])
        self.assertNotEqual(renewed["token"], self.bundle["token"])

    def test_names_and_overwrite_rejected(self):
        for hostname, origin in (("bad_name.local", "https://gcs.example"), ("ok.local", "http://gcs.example"),
                                 ("ok.local", "https://gcs.example/"), ("ok.local", "https://gcs.example:99999")):
            with self.assertRaises(ValueError): provision.validate_names(hostname, origin)
        with self.assertRaises(FileExistsError):
            provision.create_bundle(self.device, "elrs-test.local", "https://gcs.example")

    def test_import(self):
        bundle = provision.create_bundle(self.root / "imported", "elrs-test.local", "https://localhost:8443",
            cert=self.device / "device-cert.pem", key=self.device / "device-key.pem", ca_cert=self.device / "trust-ca.pem")
        self.assertEqual(bundle["certificate"], self.bundle["certificate"])
        with self.assertRaises(ValueError):
            provision.create_bundle(self.root / "mismatch", "elrs-test.local", "https://gcs.example",
                cert=self.device / "device-cert.pem", key=self.device / "ca/ca-key.pem")

    def handshake(self, hostname, trusted):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = ssl.TLSVersion.TLSv1_2
        server.load_cert_chain(self.device / "device-cert.pem", self.device / "device-key.pem")
        listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(5)
        errors = []
        def respond():
            try:
                conn, _ = listener.accept()
                with server.wrap_socket(conn, server_side=True) as tls:
                    self.assertEqual(tls.recv(4), b"test"); tls.sendall(b"okay")
            except ssl.SSLError:
                pass  # Expected for untrusted root/wrong name cases.
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=respond); thread.start()
        client = ssl.create_default_context(cafile=str(self.device / "trust-ca.pem") if trusted else None)
        try:
            with socket.create_connection(listener.getsockname(), timeout=5) as sock:
                with client.wrap_socket(sock, server_hostname=hostname) as tls:
                    tls.sendall(b"test"); self.assertEqual(tls.recv(4), b"okay")
        finally:
            thread.join(6); listener.close()
            self.assertFalse(thread.is_alive()); self.assertFalse(errors)

    def test_actual_tls_handshakes(self):
        self.handshake("elrs-test.local", True)
        self.handshake("10.0.0.1", True)  # IP SAN, without relying on mDNS.
        with self.assertRaises(ssl.SSLCertVerificationError): self.handshake("wrong.local", True)
        with self.assertRaises(ssl.SSLCertVerificationError): self.handshake("elrs-test.local", False)


if __name__ == "__main__": unittest.main()
