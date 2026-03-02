"""
Server state machine for NexaFlow nodes.

Mirrors the XRP Ledger's node state lifecycle::

    disconnected → connected → syncing → tracking → full → proposing → validating

Each state has specific semantics:
  - disconnected: not connected to any peers
  - connected: TCP connections established, HELLO exchanged
  - syncing: downloading missing ledger data
  - tracking: following the network but not yet validated
  - full: ledger state is validated and current
  - proposing: participating in consensus rounds (submitting proposals)
  - validating: fully validating (signing ledger closes)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto


class ServerState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTED    = "connected"
    SYNCING      = "syncing"
    TRACKING     = "tracking"
    FULL         = "full"
    PROPOSING    = "proposing"
    VALIDATING   = "validating"


# Valid transitions — source → set of permitted targets
_TRANSITIONS: dict[ServerState, set[ServerState]] = {
    ServerState.DISCONNECTED: {ServerState.CONNECTED},
    ServerState.CONNECTED:    {ServerState.SYNCING, ServerState.DISCONNECTED},
    ServerState.SYNCING:      {ServerState.TRACKING, ServerState.CONNECTED, ServerState.DISCONNECTED},
    ServerState.TRACKING:     {ServerState.FULL, ServerState.SYNCING, ServerState.CONNECTED, ServerState.DISCONNECTED},
    ServerState.FULL:         {ServerState.PROPOSING, ServerState.TRACKING, ServerState.SYNCING, ServerState.DISCONNECTED},
    ServerState.PROPOSING:    {ServerState.VALIDATING, ServerState.FULL, ServerState.TRACKING, ServerState.DISCONNECTED},
    ServerState.VALIDATING:   {ServerState.PROPOSING, ServerState.FULL, ServerState.TRACKING, ServerState.DISCONNECTED},
}


@dataclass
class StateEntry:
    """Accounting for time spent in a single state."""
    duration_us: int = 0
    transitions: int = 0
    entered_at: float = 0.0


class ServerStateMachine:
    """
    Tracks the current server state and records time spent in each state.

    Usage::

        sm = ServerStateMachine()
        sm.transition(ServerState.CONNECTED)
        sm.transition(ServerState.SYNCING)
        ...
        info = sm.to_dict()  # → {"server_state": "syncing", ...}
    """

    def __init__(self, initial: ServerState = ServerState.DISCONNECTED):
        self._state = initial
        self._entered_at = time.time()
        self._accounting: dict[str, StateEntry] = {}
        for s in ServerState:
            self._accounting[s.value] = StateEntry()
        self._accounting[initial.value].entered_at = self._entered_at
        self._accounting[initial.value].transitions = 1

    @property
    def state(self) -> ServerState:
        return self._state

    @property
    def state_name(self) -> str:
        return self._state.value

    def transition(self, new_state: ServerState) -> bool:
        """
        Transition to *new_state*.  Returns True on success, False if
        the transition is invalid.
        """
        if new_state == self._state:
            return True
        allowed = _TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            return False
        now = time.time()
        # Record time in previous state
        entry = self._accounting[self._state.value]
        entry.duration_us += int((now - self._entered_at) * 1_000_000)
        # Switch
        self._state = new_state
        self._entered_at = now
        new_entry = self._accounting[new_state.value]
        new_entry.transitions += 1
        new_entry.entered_at = now
        return True

    def force(self, new_state: ServerState) -> None:
        """Force a state change regardless of allowed transitions (admin)."""
        now = time.time()
        entry = self._accounting[self._state.value]
        entry.duration_us += int((now - self._entered_at) * 1_000_000)
        self._state = new_state
        self._entered_at = now
        self._accounting[new_state.value].transitions += 1
        self._accounting[new_state.value].entered_at = now

    def uptime_in_current(self) -> float:
        """Seconds spent in the current state."""
        return time.time() - self._entered_at

    def to_dict(self) -> dict:
        """Return state accounting information (rippled server_info style)."""
        now = time.time()
        # Update current state duration
        current_entry = self._accounting[self._state.value]
        current_us = current_entry.duration_us + int((now - self._entered_at) * 1_000_000)
        result = {}
        for name, entry in self._accounting.items():
            us = current_us if name == self._state.value else entry.duration_us
            result[name] = {
                "duration_us": str(us),
                "transitions": entry.transitions,
            }
        return result

    def evaluate_state(self, peer_count: int, synced: bool,
                       is_validator: bool, ledger_current: bool) -> None:
        """
        Automatically evaluate and transition state based on node conditions.

        Called periodically by the node runner.
        """
        if peer_count == 0:
            self.transition(ServerState.DISCONNECTED)
            return

        if self._state == ServerState.DISCONNECTED:
            self.transition(ServerState.CONNECTED)

        if self._state == ServerState.CONNECTED and not synced:
            self.transition(ServerState.SYNCING)
        elif self._state == ServerState.CONNECTED and synced:
            self.transition(ServerState.SYNCING)
            self.transition(ServerState.TRACKING)

        if self._state == ServerState.SYNCING and synced:
            self.transition(ServerState.TRACKING)

        if self._state == ServerState.TRACKING and ledger_current:
            self.transition(ServerState.FULL)

        if self._state == ServerState.FULL and is_validator:
            self.transition(ServerState.PROPOSING)

        if self._state == ServerState.PROPOSING and is_validator and ledger_current:
            self.transition(ServerState.VALIDATING)
