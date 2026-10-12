import http.client
import json
import threading
import unittest
from lab.app import create_server


class HTTPHardening(unittest.TestCase):
    def exercise(self, mode):
        server = create_server(mode)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=5)))
        return server.server_port

    def request(self, port, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_fixed_headers_cover_success_auth_error_and_unsupported_method(self):
        port = self.exercise('fixed')
        for method, path, expected in [('GET', '/reflect?q=hello', 200),
                                       ('GET', '/orders/1002', 401),
                                       ('TRACE', '/', 501)]:
            status, headers, body = self.request(port, method, path)
            self.assertEqual(status, expected)
            self.assertIn("form-action 'none'", headers['Content-Security-Policy'])
            self.assertIn("base-uri 'none'", headers['Content-Security-Policy'])
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(headers['Cross-Origin-Opener-Policy'], 'same-origin')
            self.assertEqual(headers['Cross-Origin-Embedder-Policy'], 'require-corp')
            self.assertEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin')
            self.assertIn('camera=()', headers['Permissions-Policy'])
            self.assertNotIn('Python', headers['Server'])
        self.assertEqual(self.request(port, 'GET', '/health')[0], 200)

    def test_fixed_login_order_and_encoded_reflection_still_work(self):
        port = self.exercise('fixed')
        status, headers, _ = self.request(port, 'POST', '/login',
            json.dumps({'username': 'alice', 'password': 'demo-password'}),
            {'Content-Type': 'application/json'})
        self.assertEqual(status, 200)
        cookie = {'Cookie': headers['Set-Cookie'].split(';', 1)[0]}
        self.assertEqual(self.request(port, 'GET', '/orders/1001', headers=cookie)[0], 200)
        self.assertEqual(self.request(port, 'GET', '/orders/1002', headers=cookie)[0], 403)
        _, _, body = self.request(port, 'GET', '/reflect?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
        self.assertIn(b'&lt;script&gt;', body)
        self.assertNotIn(b'<script>', body)

    def test_vulnerable_examples_and_headers_remain_intentional(self):
        port = self.exercise('vulnerable')
        status, headers, body = self.request(port, 'GET', '/orders/1002')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['owner_id'], 'bob')
        self.assertNotIn('Content-Security-Policy', headers)
        self.assertIn('Python', headers['Server'])
        _, _, body = self.request(port, 'GET', '/reflect?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
        self.assertIn(b'<script>alert(1)</script>', body)
