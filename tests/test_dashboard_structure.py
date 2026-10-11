"""Source-level smoke checks; integration still requires live Keycloak and FRPC."""
from pathlib import Path
import ast
import unittest

ROOT=Path(__file__).resolve().parents[1]

class DashboardStructureTests(unittest.TestCase):
    def test_sso_syntax_and_routes(self):
        source=(ROOT/"sso_app.py").read_text(encoding="utf-8")
        ast.parse(source)
        for path in ("/api/security/events","/api/health/history","/api/history"):
            self.assertIn(path,source)

    def test_dashboard_controls_and_api(self):
        source=(ROOT/"sso_app.py").read_text(encoding="utf-8")
        for item in ('id="time-filter"','id="page-size"','id="incident"',
                     'id="health-current"','id="security-rows"',
                     "function renderSecurity()","function showIncident(event)",
                     "asyncio.to_thread(get_security_events)"):
            with self.subTest(item=item):
                self.assertIn(item,source)
        self.assertIn('"/api/security/events"',source)
        self.assertIn('"/api/health/tunnels"',source)

    def test_update_syntax(self):
        ast.parse((ROOT/"update_web.py").read_text(encoding="utf-8"))

if __name__=="__main__":
    unittest.main()
