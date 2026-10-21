import unittest
from bsv_hermes import domain

class ScriptTests(unittest.TestCase):
    def test_rejects_malformed_or_unbounded_inputs(self):
        for value in ('01', '4c', '4d01', '4e010000', '4c0241', '4effffffff', ' 00', '0', 'gg', '00' * 10001, True, None):
            with self.subTest(value=str(value)[:12]), self.assertRaises(ValueError):
                domain.inspect_script(value)
        for limit in (True, 0, 101, 1.5, None):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                domain.inspect_script('00', limit)
        with self.assertRaises(ValueError):
            domain.inspect_script('00' * 100 + '01', 1)

    def test_pushdata_and_bounded_display(self):
        self.assertTrue(hasattr(domain, 'inspect_script'), 'script parser missing')
        result = domain.inspect_script('006a01414c01424d0100434e0100000044ff', 3)
        self.assertEqual(result['operation_count'], 7)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['operations'][2]['data_hex'], '41')
        self.assertEqual(result['operations'][1]['name'], 'OP_RETURN')
        self.assertEqual(domain.inspect_script('ff')['operations'][0]['name'], 'OP_UNKNOWN_FF')
        preview = domain.inspect_script('28' + 'ab' * 40)['operations'][0]
        self.assertEqual(len(preview['data_hex']), 64)
        self.assertTrue(preview['data_truncated'])
        self.assertEqual(domain.inspect_script('')['operation_count'], 0)
