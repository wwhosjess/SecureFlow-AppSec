"""Fake shop. Run with python -m lab.app --mode fixed --port 5050.

Vulnerable mode is deliberately insecure and binds to loopback only.
No dependencies, real data, uploads, subprocesses or external integrations.
"""
import argparse
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from lab import fixed_sql, vulnerable_sql

ORDERS = {
    1001: {"id": 1001, "owner_id": "alice", "item": "Studio headphones", "total": 89},
    1002: {"id": 1002, "owner_id": "bob", "item": "Mechanical keyboard", "total": 129},
}


class Shop:
    def __init__(self, mode):
        if mode not in {"fixed", "vulnerable"}:
            raise ValueError("Unknown mode")
        self.mode = mode
        self.secret = secrets.token_bytes(32)
        self.lock = threading.Lock()
        self.coupon_used = False
        self.redemptions = 0
        # Both accounts are synthetic. Passwords are derived rather than stored in cleartext.
        self.passwords = {u: hashlib.pbkdf2_hmac("sha256", b"demo-password", u.encode(), 100000)
                          for u in ("alice", "bob")}

    def login(self, user, password):
        expected = self.passwords.get(user)
        supplied = hashlib.pbkdf2_hmac("sha256", password.encode(), user.encode(), 100000)
        if expected is None or not hmac.compare_digest(expected, supplied):
            return None
        data = f"{user}:{int(time.time()) + 3600}"
        signature = hmac.new(self.secret, data.encode(), hashlib.sha256).hexdigest()
        return data + ":" + signature

    def authenticate(self, headers):
        if self.mode == "vulnerable":
            # Deliberate flaw: a browser-controlled header supplies identity.
            return headers.get("X-User", "alice")
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get("Cookie", ""))
            token = cookie["session"].value
            user, expires, signature = token.split(":")
            data = f"{user}:{expires}"
            expected = hmac.new(self.secret, data.encode(), hashlib.sha256).hexdigest()
            if int(expires) < time.time() or not hmac.compare_digest(expected, signature):
                return None
            return user if user in self.passwords else None
        except (KeyError, ValueError):
            return None

    def order(self, order_id, user):
        order = ORDERS.get(order_id)
        if order is None:
            return 404, {"error": "Order not found"}
        if self.mode == "fixed" and order["owner_id"] != user:
            return 403, {"error": "This order belongs to another account"}
        return 200, order.copy()

    def search(self, term):
        # Fresh disposable in-memory database per request.
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE products (id INTEGER, name TEXT, public INTEGER)")
            db.executemany("INSERT INTO products VALUES (?, ?, ?)", [
                (1, "Studio headphones", 1), (2, "Mechanical keyboard", 1),
                (3, "Unreleased prototype", 0)])
            if self.mode == "vulnerable":
                rows = vulnerable_sql.search(db, term)
            else:
                rows = fixed_sql.search(db, term)
        return [{"id": row[0], "name": row[1]} for row in rows]

    def reflection(self, term):
        if self.mode == "vulnerable":
            return "<h1>Search results</h1><p>" + term + "</p>"
        return "<h1>Search results</h1><p>" + html.escape(term) + "</p>"

    def redeem(self, barrier=None):
        if self.mode == "vulnerable":
            if self.coupon_used:
                return 409, {"error": "Coupon already redeemed"}
            # Deterministic test synchronization makes the race repeatable.
            if barrier:
                barrier.wait(timeout=5)
            time.sleep(0.02)
            self.coupon_used = True
            self.redemptions += 1
            return 200, {"discount": 10, "redemption": self.redemptions}
        with self.lock:
            if self.coupon_used:
                return 409, {"error": "Coupon already redeemed"}
            self.coupon_used = True
            self.redemptions += 1
            return 200, {"discount": 10, "redemption": self.redemptions}


def make_handler(shop, access_log=False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            if access_log:
                # JSON escapes scanner control characters; never log cookies or bodies.
                print(json.dumps({"time": time.time(), "thread": threading.current_thread().name,
                                  "message": fmt % args}), file=sys.stderr, flush=True)

        def version_string(self):
            return "SecureFlow" if shop.mode == "fixed" else super().version_string()

        def end_headers(self):
            if shop.mode == "fixed":
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
                self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                self.send_header("Cross-Origin-Opener-Policy", "same-origin")
                self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
                self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            super().end_headers()

        def send(self, status, body, content_type="application/json", cookie=None):
            payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            if cookie:
                # HTTP on loopback: production HTTPS must also set Secure.
                self.send_header("Set-Cookie", "session=" + cookie + "; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                return self.send(200, {"ok": True, "mode": shop.mode})
            if parsed.path == "/":
                return self.send(200, '<h1>SecureFlow local lab</h1><a href="/search?q=head">Product search</a><br><a href="/reflect?q=hello">Reflection</a>', "text/html")
            if parsed.path == "/search":
                try:
                    return self.send(200, shop.search(parse_qs(parsed.query).get("q", [""])[0]))
                except sqlite3.Error:
                    return self.send(400, {"error": "Invalid search expression"})
            if parsed.path == "/reflect":
                return self.send(200, shop.reflection(parse_qs(parsed.query).get("q", [""])[0]), "text/html")
            user = shop.authenticate(self.headers)
            if user is None:
                return self.send(401, {"error": "Valid session required"})
            if parsed.path == "/me":
                return self.send(200, {"user": user})
            if parsed.path.startswith("/orders/"):
                try:
                    status, body = shop.order(int(parsed.path.rsplit("/", 1)[-1]), user)
                except ValueError:
                    return self.send(400, {"error": "Order ID must be an integer"})
                return self.send(status, body)
            return self.send(404, {"error": "Not found"})

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 0 or size > 4096:
                    return self.send(413, {"error": "Invalid request size"})
                body = json.loads(self.rfile.read(size) or b"{}")
                if not isinstance(body, dict):
                    return self.send(400, {"error": "JSON object required"})
            except (ValueError, json.JSONDecodeError):
                return self.send(400, {"error": "Invalid JSON"})
            if self.path == "/login":
                user, password = body.get("username", ""), body.get("password", "")
                if not isinstance(user, str) or not isinstance(password, str):
                    return self.send(400, {"error": "Credentials must be strings"})
                token = shop.login(user, password)
                return self.send(200, {"user": user}, cookie=token) if token else self.send(401, {"error": "Invalid credentials"})
            if shop.authenticate(self.headers) is None:
                return self.send(401, {"error": "Valid session required"})
            if self.path == "/coupon/redeem":
                status, result = shop.redeem()
                return self.send(status, result)
            return self.send(404, {"error": "Not found"})
    return Handler


def create_server(mode, port=0, access_log=False):
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(Shop(mode), access_log))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["fixed", "vulnerable"], default="fixed")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--access-log", action="store_true", help="Log synthetic request lines/statuses for local diagnostics")
    args = parser.parse_args()
    server = create_server(args.mode, args.port, args.access_log)
    print(f"{args.mode} teaching lab: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
