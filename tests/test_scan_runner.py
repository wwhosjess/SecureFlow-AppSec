import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from security_scan import external, normalize_sca


class ScanExecution(unittest.TestCase):
    def test_duplicate_advisory_aliases_are_grouped(self):
        data = {"dependencies": [{"name": "example", "version": "1.0", "vulns": [
            {"id": "PYSEC-1", "aliases": ["CVE-1"], "fix_versions": ["2.0"]},
            {"id": "GHSA-1", "aliases": ["CVE-1"], "fix_versions": ["2.0"]}]}]}
        findings, raw = normalize_sca(data)
        self.assertEqual(raw, 2)
        self.assertEqual(len(findings), 1)
        self.assertIn("GHSA-1", findings[0]["aliases"])

    def test_missing_scanner_is_not_pass(self):
        with tempfile.TemporaryDirectory() as directory, patch('security_scan.shutil.which', return_value=None):
            result, data = external('fake', ['fake'], Path(directory) / 'report.json')
            self.assertEqual(result['status'], 'not_run')
            self.assertIsNone(data)

    def test_non_json_output_is_error(self):
        output = subprocess.CompletedProcess(['fake'], 0, stdout='not json', stderr='')
        with tempfile.TemporaryDirectory() as directory, patch('security_scan.shutil.which', return_value='/fake'), patch('security_scan.subprocess.run', return_value=output):
            result, data = external('fake', ['fake'], Path(directory) / 'report.json')
            self.assertEqual(result['status'], 'error')
            self.assertIsNone(data)

    def test_error_exit_cannot_reuse_stale_report(self):
        output = subprocess.CompletedProcess(['fake'], 2, stdout='{}', stderr='failed')
        with tempfile.TemporaryDirectory() as directory, patch('security_scan.shutil.which', return_value='/fake'), patch('security_scan.subprocess.run', return_value=output):
            path = Path(directory) / 'report.json'
            path.write_text('{"old_findings": []}')
            result, data = external('fake', ['fake'], path)
            self.assertEqual(result['status'], 'error')
            self.assertIsNone(data)

    def test_findings_exit_is_completed(self):
        output = subprocess.CompletedProcess(['fake'], 1, stdout='{"findings": [1]}', stderr='')
        with tempfile.TemporaryDirectory() as directory, patch('security_scan.shutil.which', return_value='/fake'), patch('security_scan.subprocess.run', return_value=output):
            result, data = external('fake', ['fake'], Path(directory) / 'report.json')
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(data['findings'], [1])
