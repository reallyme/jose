# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

import unittest

from check_jvm_advisories import AdvisoryError, findings, parse_locks


class AdvisoryTests(unittest.TestCase):
    def test_all_configurations_are_scanned_and_packages_are_deduplicated(self) -> None:
        queries = parse_locks(["# comment\norg.example:library:1.2.3=compile,test\nempty=runtime\n",
                              "org.example:library:1.2.3=tools\norg.example:library:2.0.0=other\n"])
        self.assertEqual(len(queries), 2)
        self.assertEqual(findings(queries, {"results": [{}, {}]}), [])

    def test_any_advisory_blocks_the_release(self) -> None:
        queries = parse_locks(["org.example:library:1.2.3=tools\n"])
        result = findings(queries, {"results": [{"vulns": [{"id": "GHSA-1234-abcd-5678"}]}]})
        self.assertEqual(result[0]["advisories"], ["GHSA-1234-abcd-5678"])

    def test_invalid_and_empty_locks_fail_closed(self) -> None:
        for source in ["", "invalid", "org:module:1.0.0=", "../private:module:1=tools"]:
            with self.assertRaises(AdvisoryError):
                parse_locks([source])

    def test_malformed_and_incomplete_responses_fail_closed(self) -> None:
        queries = parse_locks(["org.example:library:1.2.3=tools\n"])
        for result in [None, {}, {"results": []}, {"results": [None]},
                       {"results": [{"vulns": None}]}, {"results": [{"vulns": [{"id": "raw input\n"}]}]}]:
            with self.assertRaises(AdvisoryError):
                findings(queries, result)
