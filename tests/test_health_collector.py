#!/usr/bin/env python3
"""No network or production database; monitor records only transitions."""
import importlib.util
from pathlib import Path
import sqlite3
import unittest

path=Path(__file__).resolve().parents[1]/"scripts"/"health-collector.py"
spec=importlib.util.spec_from_file_location("health_collector",path)
health=importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)

class HealthTests(unittest.TestCase):
    def test_unknown_is_not_disconnected(self):
        data=health.snapshot({"proxies":[{"name":"game","type":"udp"}]},None)
        self.assertEqual(data["upstream"],"unknown")
        self.assertEqual(data["tunnels"][0]["state"],"unknown")

    def test_frps_registration_evidence(self):
        data=health.snapshot({"proxies":[{"name":"game","type":"udp"}]},
            {"udp":[{"name":"game","status":"running"}]})
        self.assertEqual(data["upstream"],"connected")

    def test_only_changes_create_events(self):
        db=sqlite3.connect(":memory:")
        first={"upstream":"connected","monitoring":"available",
               "tunnels":[{"name":"game","protocol":"udp","state":"running","reason":None}]}
        health.record(db,first,"2026-10-11T00:00:00Z")
        count=db.execute("SELECT count(*) FROM health_events").fetchone()[0]
        health.record(db,first,"2026-10-11T00:01:00Z")
        self.assertEqual(db.execute("SELECT count(*) FROM health_events").fetchone()[0],count)
        first["tunnels"][0]["state"]="error"
        health.record(db,first,"2026-10-11T00:02:00Z")
        self.assertEqual(db.execute("SELECT count(*) FROM health_events").fetchone()[0],count+1)
        db.close()

    def test_public_export_valid_json(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            original=health.PUBLIC
            health.PUBLIC=Path(folder)/"health-public.json"
            try:
                db=sqlite3.connect(":memory:")
                health.record(db,{"upstream":"unknown","monitoring":"unavailable","tunnels":[]},"2026-10-11T00:00:00Z")
                health.publish(db)
                parsed=json.loads(health.PUBLIC.read_text())
                self.assertIn("states",parsed)
                self.assertEqual(parsed["states"][0]["state"],"unknown")
                db.close()
            finally:
                health.PUBLIC=original

if __name__=="__main__":
    unittest.main()
