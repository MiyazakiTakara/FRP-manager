#!/usr/bin/env python3
"""Offline regression tests; no FRPC restart, network or production writes."""
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import tomllib
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "apply-tunnel.py"
spec = importlib.util.spec_from_file_location("frp_worker_tests", SCRIPT)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

BASE = b'''serverAddr = "example.invalid"
serverPort = 7000

[[proxies]]
name = "udp-8050"
type = "udp"
localIP = "192.168.1.37"
localPort = 8050
remotePort = 8050
'''

class WorkerTests(unittest.TestCase):
    def test_create(self):
        config = tomllib.loads(BASE.decode())
        data = {"tunnel": {"name":"demo", "protocol":"tcp", "local_ip":"192.168.1.37",
                           "local_port":20000,"public_port":20000}}
        raw, name, proto, action = worker.apply_operation(BASE, data, config)
        self.assertEqual((name,proto,action),("demo","tcp","create"))
        self.assertEqual(len(tomllib.loads(raw.decode())["proxies"]),2)

    def test_edit_preserves_unrelated_proxy(self):
        config=tomllib.loads(BASE.decode())
        target={"name":"udp-8050","protocol":"udp","local_ip":"192.168.1.37",
                "local_port":8050,"public_port":20000}
        raw,*_=worker.apply_operation(BASE,{"action":"edit","name":"udp-8050","tunnel":target},config)
        self.assertEqual(tomllib.loads(raw.decode())["proxies"][0]["remotePort"],20000)
        self.assertIn('serverAddr = "example.invalid"',raw.decode())

    def test_delete(self):
        raw,*_=worker.apply_operation(BASE,{"action":"delete","name":"udp-8050"},tomllib.loads(BASE.decode()))
        self.assertEqual(tomllib.loads(raw.decode()).get("proxies"),None)

    def test_conflicting_port(self):
        config=tomllib.loads(BASE.decode())
        bad={"tunnel":{"name":"another","protocol":"udp","local_ip":"192.168.1.37",
                       "local_port":8051,"public_port":8050}}
        with self.assertRaisesRegex(ValueError,"Remote port already used"):
            worker.apply_operation(BASE,bad,config)

    def test_port_policy(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            saved=worker.PORT_POLICY
            worker.PORT_POLICY=Path(folder)/"policy.json"
            try:
                worker.PORT_POLICY.write_text(json.dumps({"tcp":[[20000,20100]],"udp":[[8050,8050]]}))
                worker.check_port_policy("tcp",20000)
                with self.assertRaisesRegex(ValueError,"not allowed"):
                    worker.check_port_policy("tcp",8051)
            finally:
                worker.PORT_POLICY=saved

    def test_public_snapshot_contains_no_secret(self):
        secret=BASE.replace(b'serverPort = 7000',b'serverPort = 7000\nauth.token = "TOPSECRET"')
        self.assertNotIn("TOPSECRET",str(worker.public_proxies(secret)))

    def test_restore_requires_matching_live_hash(self):
        import hashlib
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            conn=sqlite3.connect(Path(d)/"history.db")
            conn.execute("CREATE TABLE versions (id INTEGER PRIMARY KEY, config BLOB, sha256 TEXT)")
            conn.execute("INSERT INTO versions VALUES (?,?,?)", (1, BASE, hashlib.sha256(BASE).hexdigest()))
            changed=BASE.replace(b"8050",b"8052")
            with self.assertRaisesRegex(ValueError,"Configuration changed"):
                worker.restore_candidate(conn, {"action":"restore","version":1,
                    "expected_sha256":hashlib.sha256(BASE).hexdigest()}, changed)
            with self.assertRaisesRegex(ValueError,"Already running"):
                worker.restore_candidate(conn, {"action":"restore","version":1,
                    "expected_sha256":hashlib.sha256(BASE).hexdigest()}, BASE)
            restored, name, proto, action = worker.restore_candidate(conn,
                {"action":"restore","version":1, "expected_sha256":hashlib.sha256(changed).hexdigest()},changed)
            self.assertEqual(restored,BASE)
            self.assertEqual(action,"restore")
            conn.close()

    def test_restore_rejects_corrupted_snapshot(self):
        import hashlib
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            conn=sqlite3.connect(Path(d)/"history.db")
            conn.execute("CREATE TABLE versions (id INTEGER PRIMARY KEY, config BLOB, sha256 TEXT)")
            conn.execute("INSERT INTO versions VALUES (?,?,?)", (1, BASE, "0"*64))
            current=BASE.replace(b"8050",b"8052")
            with self.assertRaisesRegex(ValueError,"integrity mismatch"):
                worker.restore_candidate(conn, {"action":"restore","version":1,
                    "expected_sha256":hashlib.sha256(current).hexdigest()},current)
            conn.close()

if __name__=="__main__":
    unittest.main()
