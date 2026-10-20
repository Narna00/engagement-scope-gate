import json
from pathlib import Path
import unittest
from scope_gate import decide, utc, matches, validate


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(Path(__file__).with_name('policy.example.json').read_text())
        self.now = utc('2026-06-01T00:00:00Z')

    def check(self, host, port=443, protocol='tcp', now=None):
        return decide(self.policy, {'host': host, 'port': port, 'protocol': protocol}, now or self.now)

    def test_deny_overrides_allow(self):
        self.assertEqual(self.check('192.0.2.10')['reason'], 'explicit_deny')
        self.assertEqual(self.check('payments.example.test')['reason'], 'explicit_deny')

    def test_hostname_boundaries(self):
        self.assertTrue(self.check('API.EXAMPLE.TEST.')['allowed'])
        for name in ('example.test', 'evil-example.test', 'api.example.test.attacker.test'):
            self.assertFalse(self.check(name)['allowed'])

    def test_protocol_and_port(self):
        self.assertFalse(self.check('192.0.2.1', 22)['allowed'])
        self.assertFalse(self.check('192.0.2.1', protocol='udp')['allowed'])
        self.assertTrue(self.check('192.0.2.1')['allowed'])

    def test_expiry_exclusive(self):
        self.assertFalse(self.check('192.0.2.1', now=utc(self.policy['valid_until']))['allowed'])

    def test_ipv6(self):
        self.assertTrue(matches('2001:db8::7', '2001:db8::/32'))
        self.assertFalse(matches('192.0.2.1', '2001:db8::/32'))

    def test_invalid_policy_fails_closed(self):
        self.policy['allow'] = ['192.0.2.1/24']
        with self.assertRaises(ValueError):
            validate(self.policy)
        with self.assertRaises(ValueError):
            utc('2026-01-01')


if __name__ == '__main__':
    unittest.main()
