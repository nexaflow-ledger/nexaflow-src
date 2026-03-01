"""
Ticket management for NexaFlow.

Tickets allow out-of-order sequence number usage. An account creates
tickets by consuming sequence numbers, then uses those ticket IDs
in place of sequence numbers for later transactions.

Mirrors the XRP Ledger's Tickets feature.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Ticket:
    """A single sequence reservation ticket."""
    ticket_id: str       # usually "address:sequence"
    account: str
    ticket_sequence: int  # the sequence number this ticket represents
    used: bool = False

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "account": self.account,
            "ticket_sequence": self.ticket_sequence,
            "used": self.used,
        }


class TicketManager:
    """Manages tickets for all accounts."""

    def __init__(self):
        # ticket_id -> Ticket
        self.tickets: dict[str, Ticket] = {}
        # account -> list of ticket_ids
        self._account_tickets: dict[str, list[str]] = {}

    def create_tickets(
        self, account: str, start_sequence: int, count: int,
    ) -> list[Ticket]:
        """Create `count` tickets starting at `start_sequence`."""
        created: list[Ticket] = []
        for i in range(count):
            seq = start_sequence + i
            tid = f"{account}:{seq}"
            ticket = Ticket(
                ticket_id=tid,
                account=account,
                ticket_sequence=seq,
            )
            self.tickets[tid] = ticket
            self._account_tickets.setdefault(account, []).append(tid)
            created.append(ticket)
        return created

    def use_ticket(self, ticket_id: str) -> tuple[Ticket | None, str]:
        """Mark a ticket as used. Returns (ticket, error_msg)."""
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            return None, "Ticket not found"
        if ticket.used:
            return ticket, "Ticket already used"
        ticket.used = True
        return ticket, ""

    def has_ticket(self, ticket_id: str) -> bool:
        t = self.tickets.get(ticket_id)
        return t is not None and not t.used

    def get_available_tickets(self, account: str) -> list[Ticket]:
        """Get all unused tickets for an account."""
        tids = self._account_tickets.get(account, [])
        return [self.tickets[tid] for tid in tids
                if not self.tickets[tid].used]

    def get_ticket_count(self, account: str) -> int:
        return len(self.get_available_tickets(account))
