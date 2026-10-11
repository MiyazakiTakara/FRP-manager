import importlib.util
from pathlib import Path
import json
import unittest

path=Path(__file__).resolve().parents[1]/"scripts"/"frps-security-events.py"
spec=importlib.util.spec_from_file_location("frps_security_events",path)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def line(message, micros):
    return json.dumps({"MESSAGE":message,"__REALTIME_TIMESTAMP":str(micros)})

class SecurityEventsTests(unittest.TestCase):
    def test_classifications(self):
        cases={
            "non-TLS connection received on a TlsOnly server":"tls_rejected",
            "new proxy [udp-8050] type [udp] error: acquire port 8051 error: port not allowed":"port_rejected",
            "client login info: ip [83.4.184.141:27958] version [0.71.0]":"client_login",
            "new proxy [udp-8050] type [udp] success":"proxy_created",
            "client exit success":"client_exit",
        }
        for source,expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(module.classify(source)[0],expected)

    def test_duplicates_are_aggregated(self):
        a=line("non-TLS connection received on a TlsOnly server",1760000000000000)
        result=module.read_events([a,a])
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["count"],2)

    def test_never_return_raw_log_message_or_secret(self):
        text="new proxy [udp-8050] type [udp] error: acquire port 8051 error: port not allowed secret-token-123"
        result=module.read_events([line(text,1760000000000000)])
        self.assertNotIn("secret-token-123",json.dumps(result))
        self.assertEqual(result[0]["category"],"port_rejected")

    def test_journald_byte_array_message(self):
        message="non-TLS connection received on a TlsOnly server"
        row=json.dumps({"MESSAGE":list(message.encode()),"__REALTIME_TIMESTAMP":"1791705789245574"})
        events=module.read_events([row])
        self.assertEqual(len(events),1)
        self.assertEqual(events[0]["category"],"tls_rejected")

    def test_ignore_unclassified(self):
        self.assertEqual(module.read_events([line("routine keepalive",1760000000000000)]),[])

if __name__=="__main__":
    unittest.main()
