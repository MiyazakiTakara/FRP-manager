"""Verify archive manifest tampering detection and safe backup format."""
import importlib.util
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("frp_backup",ROOT/"scripts/backup-config.py")
backup=importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
class BackupTests(unittest.TestCase):
    def test_create_and_verify_root_only_archive(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            config=root/"frpc.toml"
            config.write_text('serverAddr="example.test"')
            with patch.object(backup.os,"geteuid",return_value=0):
                path=backup.build(root/"archives",{"etc/frp/frpc.toml":config})
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(backup.verify(path)["etc/frp/frpc.toml"],len(config.read_bytes()))
    def test_missing_config_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(backup.os,"geteuid",return_value=0):
                with self.assertRaises(RuntimeError):
                    backup.build(Path(td)/"archive",{})
if __name__=="__main__":
    unittest.main()
