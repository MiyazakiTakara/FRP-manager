"""Static validation of the JavaScript actually rendered from Python templates."""
import ast
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class IDs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids=set()
    def handle_starttag(self,tag,attrs):
        for key,value in attrs:
            if key=="id":
                if value in self.ids:
                    raise AssertionError("Duplicated DOM id: "+str(value))
                self.ids.add(value)

def main_page():
    module=ast.parse((ROOT/"sso_app.py").read_text(encoding="utf-8"))
    for function in ast.walk(module):
        if isinstance(function,ast.AsyncFunctionDef) and function.name=="index":
            for node in function.body:
                if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="page" for t in node.targets):
                    return ast.literal_eval(node.value).replace("__CAN_MANAGE__","true").replace("__CAN_CREATE__","true")
    raise RuntimeError("No dashboard template")

class BrowserSmoke(unittest.TestCase):
    def test_dashboard_script_syntax(self):
        if shutil.which("node") is None:
            self.skipTest("Node.js unavailable")
        page=main_page()
        scripts=re.findall(r"<script[^>]*>(.*?)</script>",page,flags=re.S)
        self.assertEqual(len(scripts),1)
        with tempfile.TemporaryDirectory() as td:
            filename=Path(td)/"dashboard.js"
            filename.write_text(scripts[0],encoding="utf-8")
            run=subprocess.run(["node","--check",str(filename)],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)

    def test_all_dashboard_element_ids_exist(self):
        page=main_page()
        parser=IDs()
        parser.feed(page)
        used=set(re.findall(r'\$\("([a-z0-9-]+)"\)',page))
        missing=used-parser.ids
        self.assertFalse(missing,"Missing element IDs: "+", ".join(sorted(missing)))
        self.assertNotIn("<iframe",page)

if __name__=="__main__":
    unittest.main()
