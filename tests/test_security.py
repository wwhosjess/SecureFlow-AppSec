import concurrent.futures
import threading
import unittest
from lab.app import Shop


class SecurityRegression(unittest.TestCase):
    def test_own_order_is_available(self):
        self.assertEqual(Shop("fixed").order(1001, "alice")[0], 200)

    def test_cross_user_order_blocked(self):
        self.assertEqual(Shop("vulnerable").order(1002, "alice")[0], 200)
        self.assertEqual(Shop("fixed").order(1002, "alice")[0], 403)

    def test_sql_injection_and_normal_search(self):
        attack = "' OR 1=1 -- "
        self.assertTrue(any(r["id"] == 3 for r in Shop("vulnerable").search(attack)))
        self.assertEqual(Shop("fixed").search(attack), [])
        self.assertEqual(len(Shop("fixed").search("head")), 1)

    def test_reflected_content_escaped(self):
        attack = '<img src=x onerror="alert(1)">'
        self.assertIn(attack, Shop("vulnerable").reflection(attack))
        self.assertNotIn(attack, Shop("fixed").reflection(attack))
        self.assertIn("&lt;img", Shop("fixed").reflection(attack))

    def test_header_is_not_authentication(self):
        self.assertEqual(Shop("vulnerable").authenticate({"X-User": "bob"}), "bob")
        self.assertIsNone(Shop("fixed").authenticate({"X-User": "bob"}))

    def test_signed_session_and_tampering(self):
        shop = Shop("fixed")
        token = shop.login("alice", "demo-password")
        self.assertEqual(shop.authenticate({"Cookie": "session=" + token}), "alice")
        self.assertIsNone(shop.authenticate({"Cookie": "session=" + token.replace("alice", "bob")}))
        self.assertIsNone(shop.login("alice", "wrong"))

    def test_expired_session_rejected(self):
        import hashlib, hmac
        shop = Shop("fixed")
        data = "alice:1"
        token = data + ":" + hmac.new(shop.secret, data.encode(), hashlib.sha256).hexdigest()
        self.assertIsNone(shop.authenticate({"Cookie": "session=" + token}))

    def test_parallel_coupon_redemption(self):
        vulnerable = Shop("vulnerable")
        barrier = threading.Barrier(2)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(vulnerable.redeem, barrier) for _ in range(2)]
            self.assertEqual([f.result()[0] for f in futures], [200, 200])
        fixed = Shop("fixed")
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(fixed.redeem) for _ in range(2)]
            self.assertEqual(sorted(f.result()[0] for f in futures), [200, 409])
        self.assertEqual(fixed.redemptions, 1)

    def test_coupon_repeat_rejected(self):
        shop = Shop("fixed")
        self.assertEqual(shop.redeem()[0], 200)
        self.assertEqual(shop.redeem()[0], 409)


if __name__ == "__main__":
    unittest.main()
