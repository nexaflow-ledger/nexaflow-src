"""
Test suite for nexaflow_core.ticket — out-of-order sequence tickets.

Covers:
  - Ticket creation and serialization
  - TicketManager.create_tickets batch creation
  - use_ticket success and double-use
  - has_ticket
  - get_available_tickets and get_ticket_count
  - Edge cases: nonexistent ticket, zero count
"""

import unittest

from nexaflow_core.ticket import Ticket, TicketManager


class TestTicket(unittest.TestCase):

    def test_defaults(self):
        t = Ticket(ticket_id="rAlice:5", account="rAlice", ticket_sequence=5)
        self.assertFalse(t.used)
        self.assertEqual(t.ticket_sequence, 5)

    def test_to_dict(self):
        t = Ticket(ticket_id="rAlice:5", account="rAlice", ticket_sequence=5)
        d = t.to_dict()
        self.assertEqual(d["ticket_id"], "rAlice:5")
        self.assertIn("used", d)


class TestTicketManager(unittest.TestCase):

    def setUp(self):
        self.mgr = TicketManager()

    def test_create_tickets_single(self):
        tickets = self.mgr.create_tickets("rAlice", 10, 1)
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0].ticket_sequence, 10)
        self.assertEqual(tickets[0].ticket_id, "rAlice:10")

    def test_create_tickets_batch(self):
        tickets = self.mgr.create_tickets("rAlice", 5, 4)
        self.assertEqual(len(tickets), 4)
        seqs = [t.ticket_sequence for t in tickets]
        self.assertEqual(seqs, [5, 6, 7, 8])

    def test_create_tickets_zero_count(self):
        tickets = self.mgr.create_tickets("rAlice", 1, 0)
        self.assertEqual(len(tickets), 0)

    def test_use_ticket_success(self):
        self.mgr.create_tickets("rAlice", 1, 3)
        ticket, err = self.mgr.use_ticket("rAlice:2")
        self.assertEqual(err, "")
        self.assertTrue(ticket.used)

    def test_use_ticket_double_use(self):
        self.mgr.create_tickets("rAlice", 1, 1)
        self.mgr.use_ticket("rAlice:1")
        ticket, err = self.mgr.use_ticket("rAlice:1")
        self.assertNotEqual(err, "")
        self.assertIn("already used", err)

    def test_use_ticket_nonexistent(self):
        ticket, err = self.mgr.use_ticket("rAlice:999")
        self.assertIsNone(ticket)
        self.assertIn("not found", err)

    def test_has_ticket(self):
        self.mgr.create_tickets("rAlice", 1, 2)
        self.assertTrue(self.mgr.has_ticket("rAlice:1"))
        self.assertTrue(self.mgr.has_ticket("rAlice:2"))
        self.assertFalse(self.mgr.has_ticket("rAlice:3"))

    def test_has_ticket_after_use(self):
        self.mgr.create_tickets("rAlice", 1, 1)
        self.mgr.use_ticket("rAlice:1")
        self.assertFalse(self.mgr.has_ticket("rAlice:1"))

    def test_get_available_tickets(self):
        self.mgr.create_tickets("rAlice", 1, 5)
        self.assertEqual(len(self.mgr.get_available_tickets("rAlice")), 5)
        self.mgr.use_ticket("rAlice:3")
        self.assertEqual(len(self.mgr.get_available_tickets("rAlice")), 4)

    def test_get_ticket_count(self):
        self.mgr.create_tickets("rAlice", 1, 3)
        self.assertEqual(self.mgr.get_ticket_count("rAlice"), 3)
        self.mgr.use_ticket("rAlice:1")
        self.assertEqual(self.mgr.get_ticket_count("rAlice"), 2)

    def test_different_accounts_independent(self):
        self.mgr.create_tickets("rAlice", 1, 3)
        self.mgr.create_tickets("rBob", 1, 2)
        self.assertEqual(self.mgr.get_ticket_count("rAlice"), 3)
        self.assertEqual(self.mgr.get_ticket_count("rBob"), 2)


if __name__ == "__main__":
    unittest.main()
