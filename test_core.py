import unittest

from scamshield import llm, pipeline, rules


def down(msg, urls):
    raise llm.AIUnavailable("ConnectionRefusedError")


class Tests(unittest.TestCase):
    def run_(self, m="", u="", ai=down):
        return pipeline.analyze(m, u, ai_fn=ai)

    def test_empty(self):
        with self.assertRaises(ValueError): self.run_("  ")

    def test_too_long(self):
        with self.assertRaises(ValueError): self.run_("a" * 5000)

    def test_legit_low(self):
        r = self.run_("Hi, your HDFC statement for September is available in the app. Thanks.")
        self.assertEqual(r["rules"]["level"], "Low")

    def test_otp_high(self):
        self.assertEqual(self.run_("Share your OTP immediately or account blocked")["risk_level"], "High")

    def test_hinglish_hindi(self):
        self.assertEqual(self.run_("OTP bata do turant warna KYC band")["risk_level"], "High")
        self.assertTrue(rules.find_signals("आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें"))

    def test_fallback_labelled(self):
        r = self.run_("Share your OTP now")
        self.assertEqual(r["mode"], "rules-only fallback")
        self.assertIn("unavailable", r["ai"]["status"])

    def test_urls(self):
        self.assertFalse(rules.analyze_url("not a url")["valid"])
        self.assertIn("Host is a raw IP address", rules.analyze_url("http://192.168.1.5/x")["flags"])
        self.assertTrue(any("real domain" in f for f in rules.analyze_url("https://sbi-kyc.xyz/login")["flags"]))
        self.assertEqual(rules.analyze_url("https://www.sbi.co.in")["flags"], [])

    def test_validate_rejects_bad_and_drops_fake_evidence(self):
        with self.assertRaises(ValueError): llm.validate({"risk_level": "Banana"}, "x")
        ok = llm.validate({"risk_level": "High", "summary": "s", "evidence": ["real text", "invented"]}, "some real text here")
        self.assertEqual(ok["evidence"], ["real text"])

    def test_ai_cannot_lower_rule_high(self):
        ai = lambda m, u: llm.validate({"risk_level": "Low", "summary": "fine"}, m)
        self.assertEqual(self.run_("Share your OTP now", ai=ai)["risk_level"], "High")

    def test_ai_can_raise(self):
        ai = lambda m, u: llm.validate({"risk_level": "Medium", "summary": "odd"}, m)
        self.assertEqual(self.run_("Hello friend", ai=ai)["risk_level"], "Medium")


if __name__ == "__main__":
    unittest.main()
