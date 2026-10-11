"""Authentication burst aggregation (no network in tests)."""
from datetime import datetime,timezone,timedelta
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("frp_auth_alert",ROOT/"scripts/auth-alert-worker.py")
auth=importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
class AuthAlertTests(unittest.TestCase):
    def test_recent_aggregates_and_ignores_info(self):
        at=datetime(2026,10,11,12,0,tzinfo=timezone.utc)
        events=[
            {"timestamp":(at-timedelta(minutes=2)).isoformat(),"category":"authentication_failed","count":3},
            {"timestamp":(at-timedelta(minutes=2)).isoformat(),"category":"client_login","count":90},
            {"timestamp":(at-timedelta(minutes=20)).isoformat(),"category":"authentication_failed","count":5}]
        self.assertEqual(auth.summarize(events,now=at)["count"],3)
    def test_invalid_or_future_entries_ignored(self):
        at=datetime(2026,10,11,12,0,tzinfo=timezone.utc)
        events=[{"timestamp":"garbage","category":"authentication_failed","count":5},
                {"timestamp":(at+timedelta(hours=1)).isoformat(),"category":"authentication_failed","count":9}]
        self.assertEqual(auth.summarize(events,now=at)["count"],0)
if __name__=="__main__":
    unittest.main()
