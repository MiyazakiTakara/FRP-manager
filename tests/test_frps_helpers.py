"""Remote helper must never expose token or credentials."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]

def script(name):
    spec=importlib.util.spec_from_file_location(name.replace("-","_"),ROOT/"scripts"/name)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class RemoteExportTests(unittest.TestCase):
    def test_server_security_without_token_leakage(self):
        sec=script("frps-security-check.py")
        checks=sec.assess({"auth":{"method":"token","token":"super-secret-value"},
            "transport":{"tls":{"force":True}},"allowPorts":[{"single":8050}]},0o100600)
        self.assertTrue(any(x["name"]=="FRPS enforced TLS" and x["result"]=="passed" for x in checks))
        self.assertNotIn("super-secret-value",str(checks))

    def test_metrics_exporter_is_bounded(self):
        mod=script("frps-metrics.py")
        good=mod.decode_proxy({"name":"udp-8050","todayTrafficIn":1200,
                                "todayTrafficOut":500,"curConns":1,"token":"secret"})
        self.assertEqual(good["counters"]["todayTrafficIn"],1200)
        self.assertNotIn("secret",str(good))
        self.assertIsNone(mod.decode_proxy({"name":"bad/name"}))

if __name__=="__main__":
    unittest.main()
