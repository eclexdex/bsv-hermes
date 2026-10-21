import json
import unittest
from pathlib import Path
from bsv_hermes.receipts.viewer import strict_load, generate

class ParserTests(unittest.TestCase):
    def test_rejections(self):
        for raw in [b'{"x":1,"x":2}', b'{"a":{"x":1,"x":2}}', b'[]', b'{"x":NaN}', b'{"x":Infinity}', b' '*1048577, ('['*50+'0'+']'*50).encode()]:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises((ValueError,RecursionError)): strict_load(raw)
    def test_inert_generator(self):
        result=generate({'source_label':'</script><script>alert(1)</script>'})
        self.assertNotIn('</script><script>alert(1)',result)
    def test_fixture(self):
        from bsv_hermes.receipts.evidence import verify
        bundle = json.loads((Path(__file__).parent / 'receipt_vectors/contract/golden.json').read_text())
        report = verify(bundle)
        self.assertIn('results', strict_load(json.dumps(report).encode()))

if __name__=='__main__':unittest.main()
