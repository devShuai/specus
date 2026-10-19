import unittest

from verify_go_session_database_tests import (
    NATIVE_ORDER_MARKER,
    ORDER_ROOT,
    SCOPE_ROOT,
    expected_pass_tests,
    verify_events,
)


class NativeGoEvidenceTests(unittest.TestCase):
    def events(self):
        return ([{"Action": "pass", "Test": name} for name in sorted(expected_pass_tests())]
                + [{"Action": "output", "Output": NATIVE_ORDER_MARKER}, {"Action": "pass"}])

    def test_complete_native_run(self):
        self.assertEqual(verify_events(self.events())["nativeScope"], 8)

    def test_empty_output_is_not_success(self):
        with self.assertRaises(ValueError):
            verify_events([])

    def test_skipped_case_is_not_success(self):
        with self.assertRaises(ValueError):
            verify_events(self.events() + [{"Action": "skip", "Test": "hidden"}])

    def test_failed_package_is_not_success(self):
        with self.assertRaises(ValueError):
            verify_events(self.events() + [{"Action": "fail"}])

    def test_offline_scope_only_is_not_native_coverage(self):
        with self.assertRaises(ValueError):
            verify_events([event for event in self.events() if "/mysql-native" not in event.get("Test", "")])

    def test_filtered_order_case_is_not_success(self):
        with self.assertRaises(ValueError):
            verify_events([event for event in self.events() if not event.get("Test", "").startswith(ORDER_ROOT + "/")])

    def test_duplicate_case_cannot_replace_coverage(self):
        with self.assertRaises(ValueError):
            verify_events(self.events() + [{"Action": "pass", "Test": SCOPE_ROOT}])

    def test_sqlite_order_run_is_not_native_coverage(self):
        with self.assertRaises(ValueError):
            verify_events([event for event in self.events() if "Output" not in event])


if __name__ == "__main__":
    unittest.main()
