"""Tests for the transaction metadata module."""

import pytest

from nexaflow_core.tx_metadata import (
    MetadataBuilder,
    TransactionMetadata,
    AffectedNode,
    BalanceChange,
    NodeAction,
)


class MockAccountEntry:
    """Mock account entry for MetadataBuilder."""
    def __init__(self, balance, sequence, owner_count=0):
        self.balance = balance
        self.sequence = sequence
        self.owner_count = owner_count


class TestNodeAction:
    def test_enum_values(self):
        assert NodeAction.CREATED.value == "CreatedNode"
        assert NodeAction.MODIFIED.value == "ModifiedNode"
        assert NodeAction.DELETED.value == "DeletedNode"


class TestAffectedNode:
    def test_creation(self):
        node = AffectedNode(
            action=NodeAction.CREATED,
            ledger_entry_type="AccountRoot",
            ledger_index="abc123",
            new_fields={"Balance": 100.0},
        )
        assert node.action == NodeAction.CREATED
        assert node.ledger_entry_type == "AccountRoot"

    def test_to_dict(self):
        node = AffectedNode(
            NodeAction.MODIFIED, "AccountRoot", "idx",
            previous_fields={"Balance": 100.0},
            final_fields={"Balance": 200.0},
        )
        d = node.to_dict()
        assert d["action"] == "ModifiedNode"
        assert d["ledger_entry_type"] == "AccountRoot"
        assert d["previous_fields"]["Balance"] == 100.0
        assert d["final_fields"]["Balance"] == 200.0


class TestBalanceChange:
    def test_creation(self):
        bc = BalanceChange("rAlice", "NXF", "", 100.0, 50.0)
        assert bc.account == "rAlice"
        assert bc.currency == "NXF"
        assert bc.delta == -50.0

    def test_to_dict(self):
        bc = BalanceChange("rAlice", "USD", "rGateway", 0.0, 100.0)
        d = bc.to_dict()
        assert d["account"] == "rAlice"
        assert d["currency"] == "USD"
        assert d["issuer"] == "rGateway"
        assert d["delta"] == 100.0


class TestMetadataBuilder:
    def test_build_basic(self):
        builder = MetadataBuilder()
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert isinstance(meta, TransactionMetadata)
        assert meta.result_code == 0
        assert meta.result_name == "tesSUCCESS"

    def test_record_account_modify(self):
        builder = MetadataBuilder()
        acc = MockAccountEntry(500.0, 1)
        builder.snapshot_account("rAlice", acc)
        acc_after = MockAccountEntry(450.0, 2)
        builder.record_account_modify("rAlice", acc_after)
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert len(meta.affected_nodes) == 1
        assert meta.affected_nodes[0].action == NodeAction.MODIFIED

    def test_record_account_create(self):
        builder = MetadataBuilder()
        acc = MockAccountEntry(100.0, 1)
        builder.record_account_create("rNew", acc)
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert len(meta.affected_nodes) == 1
        assert meta.affected_nodes[0].action == NodeAction.CREATED

    def test_balance_changes(self):
        builder = MetadataBuilder()
        acc_a = MockAccountEntry(500.0, 1)
        acc_b = MockAccountEntry(100.0, 1)
        builder.snapshot_account("rAlice", acc_a)
        builder.snapshot_account("rBob", acc_b)
        acc_a_after = MockAccountEntry(400.0, 2)
        acc_b_after = MockAccountEntry(200.0, 2)
        builder.record_account_modify("rAlice", acc_a_after)
        builder.record_account_modify("rBob", acc_b_after)
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        changes = meta.balance_changes
        assert len(changes) == 2
        alice_change = next(c for c in changes if c.account == "rAlice")
        bob_change = next(c for c in changes if c.account == "rBob")
        assert alice_change.delta == -100.0
        assert bob_change.delta == 100.0

    def test_set_delivered_amount(self):
        builder = MetadataBuilder()
        builder.set_delivered_amount(42.5)
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert meta.delivered_amount == 42.5

    def test_record_offer_create(self):
        builder = MetadataBuilder()
        builder.record_offer_create("offer1", {"account": "rAlice",
                                                 "pair": "NXF/USD",
                                                 "amount": 100.0})
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert len(meta.affected_nodes) == 1

    def test_record_trust_line_modify(self):
        builder = MetadataBuilder()
        builder.record_trust_line_modify("rAlice:USD:rGateway",
                                          {"Balance": 500.0},
                                          {"Balance": 300.0})
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert len(meta.affected_nodes) == 1

    def test_record_generic(self):
        builder = MetadataBuilder()
        builder.record_generic(NodeAction.DELETED, "Escrow", "esc1",
                               previous_fields={"Amount": 100.0})
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert len(meta.affected_nodes) == 1
        assert meta.affected_nodes[0].action == NodeAction.DELETED


class TestTransactionMetadata:
    def test_to_dict(self):
        builder = MetadataBuilder()
        acc = MockAccountEntry(100.0, 1)
        builder.record_account_create("rNew", acc)
        builder.set_delivered_amount(100.0)
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        d = meta.to_dict()
        assert "affected_nodes" in d
        assert "balance_changes" in d
        assert d["delivered_amount"] == 100.0
        assert d["result_name"] == "tesSUCCESS"

    def test_empty_metadata(self):
        builder = MetadataBuilder()
        builder.set_result(0, "tesSUCCESS")
        meta = builder.build()
        assert len(meta.affected_nodes) == 0
        assert len(meta.balance_changes) == 0
