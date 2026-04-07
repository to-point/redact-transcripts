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

    def test_address_redaction_with_short_direction(self):
        out = redact_line(
            "Home address is 3418 W Chambers Street, Phoenix, Arizona 85041.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(out, "Home address is 123 Main Street, Phoenix, Arizona 85041.\n")

    def test_multiline_address_after_prompt(self):
        lines = [
            "[00:15 - 00:18]  Will you please confirm your property address?\n",
            "[00:18 - 00:20]  5040 El Rovio.\n",
            "[00:20 - 00:21]  That's one word.\n",
            "[00:21 - 00:23]  E-L-R-O-V as in Victor.\n",
            "[00:23 - 00:25]  I-A, Avenue.\n",
            "[00:25 - 00:29]  The city is El Monte, California, 91732.\n",
        ]
        out = _redact_multiline_email_fragments(lines, log=[], filename="x.txt")
        # Email fallback should not affect address prompt.
        self.assertEqual(out[1], lines[1])

        from redact_pii import _redact_multiline_address_fragments
        out = _redact_multiline_address_fragments(lines, log=[], filename="x.txt")
        self.assertEqual(out[1], "[00:18 - 00:20]  123 Main Street\n")
        self.assertEqual(out[3], "[00:21 - 00:23]  123 Main Street\n")
        self.assertEqual(out[4], "[00:23 - 00:25]  123 Main Street\n")
        self.assertEqual(out[5], lines[5])

    def test_ssn_redaction(self):
        out = redact_line(
            "Social security is 1381 and full is 912-81-3165.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(out, "Social security is 1234 and full is 912-81-1234.\n")

    def test_ssn_last4_after_dob_hyphen_format(self):
        out = redact_line(
            "Thank you, and date of birth and last four social? 9-26-1989-6320.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(
            out,
            "Thank you, and date of birth and last four social? 9-26-1989-1234.\n",
        )

    def test_ssn_last4_after_compact_dob_token(self):
        out = redact_line(
            "And then just your date of birth and last four of social, please. 1730771223.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(
            out,
            "And then just your date of birth and last four of social, please. 1730771234.\n",
        )

    def test_ssn_last4_dash_separated_digits(self):
        out = redact_line(
            "And then the last four of your social security number. 9-1-5-4.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(
            out,
            "And then the last four of your social security number. 1-2-3-4.\n",
        )

    def test_inline_address_after_prompt_with_dashed_number(self):
        out = redact_line(
            "verify your property address? 1-4-0-8-5 Stoudridge, Lawrenceville, Georgia, 3-0-0-4-5.\n",
            log=[],
            filename="x.txt",
            lineno=1,
        )
        self.assertEqual(
            out,
            "verify your property address? 123 Main Street, Lawrenceville, Georgia, 3-0-0-4-5.\n",
        )

    def test_multiline_address_does_not_cross_into_social_prompt(self):
        from redact_pii import _redact_multiline_address_fragments

        lines = [
            "[00:43 - 00:47]  So, I just need to verify your full name and full property address, please.\n",
            "[00:47 - 00:53]  5040 El Rovio Avenue.\n",
            "[00:53 - 00:58]  And then just your date of birth and last four of social, please.\n",
            "[00:58 - 00:59]  1730771223.\n",
        ]
        out = _redact_multiline_address_fragments(lines, log=[], filename="x.txt")
        self.assertEqual(out[1], "[00:47 - 00:53]  123 Main Street\n")
        self.assertEqual(out[2], lines[2])
        self.assertEqual(out[3], lines[3])

    def test_multiline_ssn_after_social_prompt(self):
        from redact_pii import _redact_multiline_ssn_fragments

        lines = [
            "[00:29 - 00:34]  Perfect. And if you could also verify your date of birth and the last four of your social, and we'll be all set.\n",
            "[00:34 - 00:39]  Yes. February 19, 1973, 5257.\n",
            "[00:39 - 00:42]  Great, thank you.\n",
        ]
        out = _redact_multiline_ssn_fragments(lines, log=[], filename="x.txt")
        self.assertEqual(out[1], "[00:34 - 00:39]  Yes. February 19, 1973, 1234.\n")
        self.assertEqual(out[2], lines[2])


if __name__ == "__main__":
    unittest.main()
