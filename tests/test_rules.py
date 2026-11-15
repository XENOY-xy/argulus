# 只测纯函数，不联网，不装第三方依赖也能跑
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan import sig, same, blind, find_params, private_host
from neteyes import parse_ports, private_host as gui_private_host


def resp(code, text):
    return SimpleNamespace(status_code=code, text=text,
                           headers={"Content-Type": "text/html"})


class RulesTest(unittest.TestCase):

    def test_sig_normalizes_digits_and_space(self):
        self.assertEqual(sig(resp(200, "a=12\n  b=9")), (200, "a=0 b=0"))

    def test_sig_rejects_none_and_5xx(self):
        self.assertIsNone(sig(None))
        self.assertIsNone(sig(resp(500, "boom")))

    def test_same_gates(self):
        a = (200, "x" * 50)
        self.assertTrue(same(a, (200, "x" * 50)))
        self.assertFalse(same(a, None))
        self.assertFalse(same(a, (404, "x" * 50)))
        self.assertFalse(same(a, (200, "x" * 400)))  # 长度差超过 200，直接否

    def test_blind_true(self):
        b = (200, "A" * 100)
        ts = [(200, "A" * 100), (200, "A" * 100)]
        fs = [(200, "B" * 100), (200, "B" * 100)]
        self.assertTrue(blind(b, ts, fs))

    def test_blind_rejects_forged_pages(self):
        b = (200, "A" * 100)
        ts = [(200, "A" * 100), (200, "A" * 100)]
        fs = [(200, "B" * 100), (200, "B" * 100)]
        self.assertFalse(blind(b, [ts[0], fs[0]], fs))  # 恒真里混进一个恒假
        self.assertFalse(blind(b, ts, [fs[0], b]))       # 恒假里混回基线
        self.assertFalse(blind(None, ts, fs))

    def test_find_params_dedup(self):
        html = '<input name="id"><input name="page"><a href="/?id=1&q=2">x</a>'
        got = find_params(html)
        self.assertEqual(got, ["id", "page"])
        self.assertEqual(len(got), len(set(got)))
        self.assertNotIn("q", got)  # 单字母参数名会被过滤掉

    def test_private_host(self):
        for ok in ("127.0.0.1", "192.168.1.0/24", "10.0.0.0/8", "169.254.0.0/16", "::1"):
            self.assertTrue(private_host(ok), ok)
        for bad in ("8.8.8.8", "example.com", "localhost", "", "999.1.1.1"):
            self.assertFalse(private_host(bad), bad)

    def test_parse_ports(self):
        self.assertEqual(parse_ports("80,443,80-82"), [80, 81, 82, 443])
        self.assertEqual(parse_ports("90-88"), [88, 89, 90])
        self.assertEqual(parse_ports("abc,70000,-1,,  "), [])
        self.assertEqual(parse_ports(""), [])

    def test_gui_private_host_matches(self):
        for h in ("127.0.0.1", "192.168.1.0/24", "8.8.8.8", "example.com"):
            self.assertEqual(gui_private_host(h), private_host(h), h)


if __name__ == "__main__":
    unittest.main()
