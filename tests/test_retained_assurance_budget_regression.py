import unittest
import tracemalloc
from bsv_hermes.kits.assurance import core

class BudgetTests(unittest.TestCase):

    def test_escaped_native_string_rejected_before_allocation(self):
        value = '\x00' * (2 * 1024 * 1024)
        tracemalloc.start()
        try:
            with self.assertRaises(core.Invalid):
                core.bounded(value)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 1024 * 1024)

    def test_depth_and_node_budget(self):
        value = 0
        for _ in range(100):
            value = [value]
        for bad in (value, [0] * 20000, {'x': float('nan')}, {1: 'x'}):
            with self.subTest(kind=type(bad)), self.assertRaises(core.Invalid):
                core.bounded(bad)

    def test_canonical_budget_boundaries(self):
        self.assertEqual(len(core.bounded('a' * 65534)), 65536)
        with self.assertRaises(core.Invalid):
            core.bounded('a' * 65535)
        self.assertEqual(core.bounded({'x': '\x00é😀'}), b'{"x":"\\u0000\\u00e9\\ud83d\\ude00"}')
