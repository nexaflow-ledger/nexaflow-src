"""
Shared pytest fixtures for the NexaFlow test suite.
"""

import pytest

from nexaflow_core.ledger import Ledger
from nexaflow_core.wallet import Wallet
from nexaflow_core.account import Account
from nexaflow_core.trust_line import TrustGraph
from nexaflow_core.validator import TransactionValidator


@pytest.fixture
def ledger():
    """Fresh ledger with 10k NXF supply and genesis account."""
    return Ledger(total_supply=10_000.0, genesis_account="rGen")


@pytest.fixture
def funded_ledger(ledger):
    """Ledger with pre-funded accounts."""
    ledger.create_account("rAlice", 500.0)
    ledger.create_account("rBob", 100.0)
    ledger.create_account("rGateway", 200.0)
    return ledger


@pytest.fixture
def wallet():
    """Fresh wallet."""
    return Wallet.create()


@pytest.fixture
def alice_wallet():
    """Deterministic wallet for Alice."""
    return Wallet.from_seed("alice-fixture-seed")


@pytest.fixture
def account():
    """Fresh account."""
    return Account.create()


@pytest.fixture
def trust_graph(funded_ledger):
    """Trust graph built from funded ledger with some trust lines."""
    funded_ledger.set_trust_line("rAlice", "USD", "rGateway", 1000.0)
    funded_ledger.set_trust_line("rBob", "USD", "rGateway", 500.0)
    graph = TrustGraph()
    graph.build_from_ledger(funded_ledger)
    return graph


@pytest.fixture
def validator(funded_ledger):
    """Transaction validator against the funded ledger."""
    return TransactionValidator(funded_ledger)
