"""
Network & Node management for NexaFlow.

Simulates a peer-to-peer network of validator nodes.
Each node maintains its own ledger, wallet, and consensus engine.
Transactions are broadcast to all peers, and consensus is run
collaboratively to close ledgers.

This is a local simulation — no actual sockets are used.
"""

from __future__ import annotations

import copy
import time
from typing import Dict, List, Optional, Set

from nexaflow_core.wallet import Wallet
from nexaflow_core.ledger import Ledger
from nexaflow_core.consensus import ConsensusEngine, Proposal
from nexaflow_core.transaction import Transaction
from nexaflow_core.validator import TransactionValidator
from nexaflow_core.trust_line import TrustGraph
from nexaflow_core.payment_path import PathFinder


class ValidatorNode:
    """
    A single validator node in the NexaFlow network.

    Holds its own copy of the ledger, a transaction pool,
    and participates in consensus rounds.
    """

    def __init__(self, node_id: str, ledger: Ledger, unl: Optional[List[str]] = None):
        self.node_id = node_id
        self.ledger = ledger
        self.unl: List[str] = unl or []
        self.tx_pool: Dict[str, Transaction] = {}  # tx_id -> Transaction
        self.validator = TransactionValidator(ledger)
        self.trust_graph = TrustGraph()
        self.closed_count = 0

    def receive_transaction(self, tx: Transaction) -> tuple:
        """
        Receive and validate a transaction.
        Returns (accepted: bool, code: int, message: str).
        """
        valid, code, msg = self.validator.validate(tx)
        if valid:
            self.tx_pool[tx.tx_id] = tx
        return valid, code, msg

    def create_proposal(self) -> Proposal:
        """Create a consensus proposal from our transaction pool."""
        tx_ids = set(self.tx_pool.keys())
        return Proposal(self.node_id, self.ledger.current_sequence, tx_ids)

    def apply_consensus_result(self, agreed_tx_ids: Set[str]) -> List[Transaction]:
        """
        Apply the agreed transactions to our ledger and close it.
        Returns list of applied transactions.
        """
        applied: List[Transaction] = []
        for tx_id in agreed_tx_ids:
            tx = self.tx_pool.get(tx_id)
            if tx is not None:
                result = self.ledger.apply_transaction(tx)
                if result == 0:
                    applied.append(tx)

        # Close the ledger
        self.ledger.close_ledger()
        self.closed_count += 1

        # Clear applied txns from pool
        for tx in applied:
            self.tx_pool.pop(tx.tx_id, None)

        # Rebuild trust graph
        self.trust_graph.build_from_ledger(self.ledger)

        return applied

    def get_path_finder(self) -> PathFinder:
        """Get a path finder for the current trust graph."""
        self.trust_graph.build_from_ledger(self.ledger)
        return PathFinder(self.trust_graph, self.ledger)

    def status(self) -> dict:
        return {
            "node_id": self.node_id,
            "ledger_seq": self.ledger.current_sequence,
            "closed_ledgers": self.closed_count,
            "pending_txns": len(self.tx_pool),
            "accounts": len(self.ledger.accounts),
            "unl_size": len(self.unl),
        }


class Network:
    """
    Simulated NexaFlow peer-to-peer network.

    Manages multiple ValidatorNodes, broadcasts transactions,
    and orchestrates consensus rounds.
    """

    def __init__(self, total_supply: float = 100_000_000_000.0):
        self.nodes: Dict[str, ValidatorNode] = {}
        self.total_supply = total_supply
        self._base_ledger: Optional[Ledger] = None

    def add_validator(self, node_id: str) -> ValidatorNode:
        """Add a new validator node to the network."""
        if self._base_ledger is None:
            self._base_ledger = Ledger(self.total_supply)

        # Each node gets a deep copy of the ledger so they're independent
        ledger = Ledger(self.total_supply)
        # Copy genesis state
        for addr, acc in self._base_ledger.accounts.items():
            if addr not in ledger.accounts:
                ledger.create_account(addr, acc.balance)
                ledger.accounts[addr].is_gateway = acc.is_gateway

        node = ValidatorNode(node_id, ledger)
        self.nodes[node_id] = node

        # Update UNLs — every node trusts every other (full mesh)
        all_ids = list(self.nodes.keys())
        for nid, n in self.nodes.items():
            n.unl = [x for x in all_ids if x != nid]

        return node

    def broadcast_transaction(self, tx: Transaction) -> Dict[str, tuple]:
        """Send a transaction to all validator nodes."""
        results: Dict[str, tuple] = {}
        for nid, node in self.nodes.items():
            results[nid] = node.receive_transaction(tx)
        return results

    def run_consensus_round(self) -> dict:
        """
        Run a full consensus round across all nodes:
          1. Each node creates a proposal
          2. Proposals are shared with all peers
          3. Each node runs its consensus engine
          4. Agreed transactions are applied
        Returns summary dict.
        """
        if not self.nodes:
            return {"error": "No validators"}

        node_list = list(self.nodes.values())
        all_ids = list(self.nodes.keys())

        # Step 1: Each node creates a proposal
        proposals: Dict[str, Proposal] = {}
        for node in node_list:
            proposals[node.node_id] = node.create_proposal()

        # Step 2-3: Each node runs consensus with all proposals
        agreed_tx_ids: Optional[Set[str]] = None

        for node in node_list:
            engine = ConsensusEngine(
                node.unl, node.node_id, node.ledger.current_sequence
            )
            # Submit own transactions
            engine.submit_transactions(list(node.tx_pool.keys()))
            # Add peer proposals
            for pid, prop in proposals.items():
                if pid != node.node_id:
                    engine.add_proposal(prop)

            result = engine.run_rounds()
            if result is not None:
                # Use the first successful consensus result
                if agreed_tx_ids is None:
                    agreed_tx_ids = result.agreed_tx_ids

        if agreed_tx_ids is None:
            return {"status": "no_consensus", "agreed": 0}

        # Step 4: All nodes apply the agreed transactions
        total_applied = 0
        for node in node_list:
            # Share the transaction objects across nodes
            for tx_id in agreed_tx_ids:
                if tx_id not in node.tx_pool:
                    # Find the tx from another node
                    for other in node_list:
                        if tx_id in other.tx_pool:
                            node.tx_pool[tx_id] = other.tx_pool[tx_id]
                            break

            applied = node.apply_consensus_result(agreed_tx_ids)
            total_applied = max(total_applied, len(applied))

        return {
            "status": "consensus_reached",
            "agreed_transactions": len(agreed_tx_ids),
            "applied_transactions": total_applied,
            "ledger_sequence": node_list[0].ledger.current_sequence,
        }

    def fund_account(self, address: str, amount: float) -> None:
        """Fund an account from genesis on all nodes (test helper)."""
        for node in self.nodes.values():
            if not node.ledger.account_exists(address):
                node.ledger.create_account(address, 0.0)
            genesis = node.ledger.get_account(node.ledger.genesis_account)
            dest = node.ledger.get_account(address)
            if genesis is not None and dest is not None:
                if genesis.balance >= amount:
                    genesis.balance -= amount
                    dest.balance += amount

    def network_status(self) -> dict:
        return {
            "validators": len(self.nodes),
            "nodes": {nid: n.status() for nid, n in self.nodes.items()},
        }
