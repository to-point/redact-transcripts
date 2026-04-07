import unittest

from redact_pii import _redact_multiline_email_fragments, redact_line


class RedactPiiTests(unittest.TestCase):
    def test_multiline_spelled_email_after_prompt(self):
        lines = [
            "[00:50 - 00:52]  And I just need the e-mail address used on your estimate as well.\n",
            "[00:52 - 00:54]  It is F, like Fran,\n",
            "[00:54 - 00:56]  R-A-N-M-E-E-H-A-N\n",
            "[00:56 - 00:58]  dot F-M.\n",
            "[00:58 - 01:00]  Perfect.\n",
        ]
        out = _redact_multiline_email_fragments(lines, log=[], filename="x.txt")

        self.assertEqual(out[1], "[00:52 - 00:54]  email@me.com\n")
        self.assertEqual(out[2], "[00:54 - 00:56]  email@me.com\n")
        self.assertEqual(out[3], "[00:56 - 00:58]  email@me.com\n")
        self.assertEqual(out[4], "[00:58 - 01:00]  Perfect.\n")

    def test_single_line_email_simple(self):
        out = redact_line(
            "Please use derek.j.simmons at gmail.com for follow up.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(out, "Please use email@me.com for follow up.\n")

    def test_provider_email_token(self):
        out = redact_line(
            "The account is gallegospeet.sbcglobal.net.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(out, "The account is email@me.com.\n")

    def test_address_redaction(self):
        out = redact_line(
            "Ship it to 5741 Carriage Court in town.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(out, "Ship it to 123 Main Street in town.\n")

    def test_ssn_redaction(self):
        out = redact_line(
            "Social security is 1381 and full is 912-81-3165.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(out, "Social security is 1234 and full is 912-81-1234.\n")


if __name__ == "__main__":
    unittest.main()
