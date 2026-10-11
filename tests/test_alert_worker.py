"""State-based notification tests; no network traffic."""
import importlib.util
from datetime import datetime,timezone
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("frp_alert_worker",ROOT/"scripts/alert-worker.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class AlertTests(unittest.TestCase):
    def test_initial_baseline_sends_nothing(self):
        self.assertEqual(module.changes({"states":{},"sent":{}},{"frps_connection":"disconnected"},1000),[])
    def test_disconnection_alert_and_deduplication(self):
        before={"states":{"frps_connection":"connected"},"sent":{}}
        self.assertEqual(module.changes(before,{"frps_connection":"disconnected"},1000),[("frps_connection","disconnected")])
        before["sent"]["frps_connection:disconnected"]=800
        self.assertEqual(module.changes(before,{"frps_connection":"disconnected"},1000),[])
    def test_recovery_is_not_a_critical_alert(self):
        self.assertEqual(module.changes({"states":{"collector":"stale"},"sent":{}},{"collector":"available"},1000),[])
    def test_maintenance_window_suppresses_only_named_proxy(self):
        before={"states":{"proxy:udp:udp-8050":"running","frps_connection":"connected"},"sent":{}}
        after={"proxy:udp:udp-8050":"error","frps_connection":"unknown"}
        alerts=module.changes(before,after,1000,maintenance={"udp-8050"})
        self.assertNotIn(("proxy:udp:udp-8050","error"),alerts)
        self.assertIn(("frps_connection","unknown"),alerts)

    def test_stale_monitoring(self):
        data={"sampled_at":"2025-01-01T00:00:00+00:00","states":[]}
        self.assertEqual(module.parse(data,datetime(2026,1,1,tzinfo=timezone.utc)),{"collector":"stale"})
if __name__=="__main__":
    unittest.main()
