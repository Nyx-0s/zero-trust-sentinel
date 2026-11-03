import unittest

from mellenth_os import classify_reply


class ReplyClassificationTests(unittest.TestCase):
    def test_opt_out_wins(self):
        self.assertEqual(classify_reply("Please unsubscribe me")[0], "opt_out")

    def test_meeting_request(self):
        self.assertEqual(classify_reply("Can we book a demo next week?")[0], "meeting_request")

    def test_interest(self):
        self.assertEqual(classify_reply("Please send pricing details")[0], "interested")

    def test_objection(self):
        self.assertEqual(classify_reply("We have no budget this quarter")[0], "objection")

    def test_needs_review_default(self):
        self.assertEqual(classify_reply("Thanks for the note")[0], "needs_review")


if __name__ == "__main__":
    unittest.main()
