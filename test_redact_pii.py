import unittest

from redact_pii import (
    _redact_multiline_address_fragments,
    _redact_multiline_email_fragments,
    _redact_multiline_names,
    _redact_multiline_ssn_fragments,
    redact_line,
)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class EmailTests(unittest.TestCase):
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
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "Please use email@me.com for follow up.\n")

    def test_provider_email_token(self):
        out = redact_line(
            "The account is gallegospeet.sbcglobal.net.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "The account is email@me.com.\n")

    def test_email_embedded_at_no_space(self):
        """Email where digit/symbol runs into 'at' with no preceding space."""
        out = redact_line(
            "link on your email, which is danielkoronko61at yahoo.com.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("email@me.com", out)
        self.assertNotIn("danielkoronko61at", out)

    def test_common_word_not_matched_as_email(self):
        """'that gmail.com' must not be redacted — 'that' has no digit/symbol."""
        out = redact_line(
            "Check that gmail.com is correct.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("gmail.com", out)


# ---------------------------------------------------------------------------
# Address
# ---------------------------------------------------------------------------

class AddressTests(unittest.TestCase):
    def test_address_redaction(self):
        out = redact_line(
            "Ship it to 5741 Carriage Court in town.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "Ship it to 123 Main Street in town.\n")

    def test_address_with_direction(self):
        out = redact_line(
            "Home address is 3418 W Chambers Street, Phoenix, Arizona 85041.\n",
            log=[], filename="x.txt", lineno=1,
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
        out = _redact_multiline_address_fragments(lines, log=[], filename="x.txt")
        self.assertEqual(out[1], "[00:18 - 00:20]  123 Main Street\n")
        self.assertEqual(out[3], "[00:21 - 00:23]  123 Main Street\n")
        self.assertEqual(out[4], "[00:23 - 00:25]  123 Main Street\n")
        self.assertEqual(out[5], lines[5])

    def test_multiline_address_does_not_cross_into_social_prompt(self):
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

    def test_inline_address_after_prompt_with_dashed_number(self):
        out = redact_line(
            "verify your property address? 1-4-0-8-5 Stoudridge, Lawrenceville, Georgia, 3-0-0-4-5.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(
            out,
            "verify your property address? 123 Main Street, Lawrenceville, Georgia, 3-0-0-4-5.\n",
        )


# ---------------------------------------------------------------------------
# SSN
# ---------------------------------------------------------------------------

class SSNTests(unittest.TestCase):
    def test_ssn_full_and_last4(self):
        out = redact_line(
            "Social security is 1381 and full is 912-81-3165.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "Social security is 1234 and full is 912-81-1234.\n")

    def test_ssn_last4_after_dob_hyphen_format(self):
        out = redact_line(
            "Thank you, and date of birth and last four social? 9-26-1989-6320.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(
            out,
            "Thank you, and date of birth and last four social? 9-26-1989-1234.\n",
        )

    def test_ssn_last4_after_compact_dob_token(self):
        out = redact_line(
            "And then just your date of birth and last four of social, please. 1730771223.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(
            out,
            "And then just your date of birth and last four of social, please. 1730771234.\n",
        )

    def test_ssn_last4_dash_separated_digits(self):
        out = redact_line(
            "And then the last four of your social security number. 9-1-5-4.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(
            out,
            "And then the last four of your social security number. 1-2-3-4.\n",
        )

    def test_multiline_ssn_after_social_prompt(self):
        lines = [
            "[00:29 - 00:34]  Perfect. And if you could also verify your date of birth and the last four of your social, and we'll be all set.\n",
            "[00:34 - 00:39]  Yes. February 19, 1973, 5257.\n",
            "[00:39 - 00:42]  Great, thank you.\n",
        ]
        out = _redact_multiline_ssn_fragments(lines, log=[], filename="x.txt")
        # DOB should now be redacted too, and SSN4 replaced
        self.assertEqual(out[1], "[00:34 - 00:39]  Yes. [DOB], 1234.\n")
        self.assertEqual(out[2], lines[2])

    def test_ssn_last4_inline_on_same_line(self):
        out = redact_line(
            "And the last four digits of my social is 8424.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "And the last four digits of my social is 1234.\n")


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

class PhoneTests(unittest.TestCase):
    def test_phone_formatted_dash(self):
        out = redact_line(
            "Call back number is 928-261-2238.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "Call back number is [PHONE].\n")

    def test_phone_formatted_dot(self):
        out = redact_line(
            "Her number is 818.430.5307.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "Her number is [PHONE].\n")

    def test_phone_spoken_dashes(self):
        out = redact_line(
            "Phone number is 2-0-3-6-2-7-6-8-3-6.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "Phone number is [PHONE].\n")

    def test_phone_confirmed_callback(self):
        out = redact_line(
            "And your best call back number is 757-667-8932.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "And your best call back number is [PHONE].\n")

    def test_phone_repeated_twice(self):
        """Both occurrences of the same number on one line are redacted."""
        out = redact_line(
            "So 330-556-2923 confirmed, 330-556-2923.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "So [PHONE] confirmed, [PHONE].\n")


# ---------------------------------------------------------------------------
# Dates of birth
# ---------------------------------------------------------------------------

class DOBTests(unittest.TestCase):
    def test_dob_named_month(self):
        out = redact_line(
            "My date of birth is November 10, 1967.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertEqual(out, "My date of birth is [DOB].\n")

    def test_dob_named_month_ordinal(self):
        out = redact_line(
            "Birthday is March 7th, 1963.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[DOB]", out)
        self.assertNotIn("March 7th, 1963", out)

    def test_dob_with_ssn4_combined(self):
        """Named-month DOB immediately followed by SSN4 on same line."""
        out = redact_line(
            "April 6, 1934-6313.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[DOB]", out)
        self.assertIn("1234", out)
        self.assertNotIn("6313", out)
        self.assertNotIn("April 6, 1934", out)

    def test_dob_named_month_ssn4_comma(self):
        """February 10th, 1977, 7405"""
        out = redact_line(
            "My birthday is February 10th, 1977, 7405.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[DOB]", out)
        self.assertIn("1234", out)
        self.assertNotIn("7405", out)

    def test_dob_compact_numeric_context(self):
        """Compact numeric DOB in 'date of birth is' context."""
        out = redact_line(
            "Date of birth is 11, 15, 59, last four, 8814.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[DOB]", out)
        # 8814 caught by SSN_LAST4_CONTEXT
        self.assertIn("1234", out)
        self.assertNotIn("11, 15, 59", out)
        self.assertNotIn("8814", out)

    def test_dob_compact_birthday_keyword(self):
        out = redact_line(
            "birthday is 122373. Last four is 0029.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[DOB]", out)
        self.assertIn("1234", out)
        self.assertNotIn("122373", out)

    def test_dob_compact_0614(self):
        out = redact_line(
            "birthday 0614, 1961, last four digits, 8814.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[DOB]", out)
        self.assertNotIn("0614", out)

    def test_dob_multiline_ssn_also_redacts_dob(self):
        """The multiline SSN pass should also clear the named-month DOB."""
        lines = [
            "[00:29 - 00:34]  Could you verify your date of birth and last four of social?\n",
            "[00:34 - 00:39]  January 12, 1960, 9387.\n",
        ]
        out = _redact_multiline_ssn_fragments(lines, log=[], filename="x.txt")
        self.assertIn("[DOB]", out[1])
        self.assertIn("1234", out[1])
        self.assertNotIn("January 12, 1960", out[1])
        self.assertNotIn("9387", out[1])


# ---------------------------------------------------------------------------
# Customer names
# ---------------------------------------------------------------------------

class NameTests(unittest.TestCase):
    def test_name_inline_my_name_is(self):
        out = redact_line(
            "Yes, my name is Allison Vance and I was wondering about my application.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[Name]", out)
        self.assertNotIn("Allison Vance", out)

    def test_name_inline_first_and_last_name_is(self):
        out = redact_line(
            "First and last name is Doris Eads.\n",
            log=[], filename="x.txt", lineno=1,
        )
        self.assertIn("[Name]", out)
        self.assertNotIn("Doris Eads", out)

    def test_name_multiline_after_request(self):
        lines = [
            "[00:18 - 00:21]  May I have your first and last name?\n",
            "[00:21 - 00:23]  Daniel Carranco.\n",
        ]
        out = _redact_multiline_names(lines, log=[], filename="x.txt")
        self.assertIn("[Name]", out[1])
        self.assertNotIn("Daniel Carranco", out[1])

    def test_name_multiline_with_okay_filler(self):
        """Name appears 2 lines after request (with 'Okay' in between)."""
        lines = [
            "[01:25 - 01:28]  May I have your first and last names, so that I could check?\n",
            "[01:30 - 01:30]  Okay.\n",
            "[01:30 - 01:32]  John Stokes.\n",
        ]
        out = _redact_multiline_names(lines, log=[], filename="x.txt")
        self.assertIn("[Name]", out[2])
        self.assertNotIn("John Stokes", out[2])

    def test_name_multiline_does_not_redact_address(self):
        """An address response after a name prompt should NOT be treated as a name."""
        lines = [
            "[00:18 - 00:21]  May I have your first and last name?\n",
            "[00:21 - 00:27]  1934 West 19th Street, Yuma, Arizona.\n",
        ]
        out = _redact_multiline_names(lines, log=[], filename="x.txt")
        # Address starts with house number, so _looks_like_name_response returns False
        self.assertNotIn("[Name]", out[1])

    def test_single_word_response_not_a_name(self):
        """A single word (agent first name / place name) should not be redacted as customer name."""
        lines = [
            "[00:04 - 00:06]  May I have your name?\n",
            "[00:06 - 00:07]  California.\n",
        ]
        out = _redact_multiline_names(lines, log=[], filename="x.txt")
        self.assertNotIn("[Name]", out[1])


if __name__ == "__main__":
    unittest.main()
