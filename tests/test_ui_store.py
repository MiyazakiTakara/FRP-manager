"""Metadata storage contracts: no changes to FRPC configuration."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import ui_store

class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env=patch.dict(os.environ,{"FRP_MANAGER_UI_DB":str(Path(self.temp.name)/"state.db")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_crud_and_unicode(self):
        self.assertEqual(ui_store.read("udp-8050")["description"],"")
        saved=ui_store.update("udp-8050","Game server",["Games","Production"],None,"admin123")
        self.assertEqual(saved["tags"],["Games","Production"])
        self.assertEqual(ui_store.list_all()["udp-8050"]["description"],"Game server")

    def test_reject_duplicate_tags_and_invalid_name(self):
        with self.assertRaises(ValueError):
            ui_store.update("bad/name","",[],None,"admin")
        with self.assertRaises(ValueError):
            ui_store.update("udp-8050","",["Prod","Prod"],None,"admin")

    def test_maintenance_date_within_month(self):
        now=datetime.now(timezone.utc)
        stamp=(now+timedelta(days=2)).isoformat()
        result=ui_store.update("udp-8050","",[],stamp,"admin")
        self.assertIsNotNone(result["maintenance_until"])
        with self.assertRaises(ValueError):
            ui_store.update("udp-8050","",[],(now+timedelta(days=40)).isoformat(),"admin")

    def test_no_implicit_directory_creation(self):
        with patch.dict(os.environ,{"FRP_MANAGER_UI_DB":str(Path(self.temp.name)/"missing"/"state.db")}):
            with self.assertRaises(RuntimeError):
                ui_store.read("udp-8050")

if __name__=="__main__":
    unittest.main()
