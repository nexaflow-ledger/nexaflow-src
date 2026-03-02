"""Tests for the DID (Decentralized Identifiers) module."""

import pytest

from nexaflow_core.did import DIDDocument, DIDManager


@pytest.fixture
def dids():
    return DIDManager()


class TestDIDSet:
    def test_set_did_uri(self, dids):
        ok, msg, did = dids.set_did("rAlice", uri="https://example.com/did")
        assert ok is True
        assert did is not None
        assert did.account == "rAlice"
        assert did.uri == "https://example.com/did"

    def test_set_did_data(self, dids):
        ok, msg, did = dids.set_did("rAlice", data="deadbeef")
        assert ok is True
        assert did.data == "deadbeef"

    def test_set_did_empty_creates_default(self, dids):
        ok, msg, did = dids.set_did("rAlice")
        assert ok is True
        assert did.uri == ""
        assert did.data == ""

    def test_update_did(self, dids):
        dids.set_did("rAlice", uri="v1")
        ok, msg, did = dids.set_did("rAlice", uri="v2")
        assert ok is True
        assert did.uri == "v2"


class TestDIDDelete:
    def test_delete_did(self, dids):
        dids.set_did("rAlice", uri="test")
        ok, msg = dids.delete_did("rAlice")
        assert ok is True
        assert dids.get_did("rAlice") is None

    def test_delete_nonexistent(self, dids):
        ok, msg = dids.delete_did("rNobody")
        assert ok is False


class TestDIDResolve:
    def test_resolve_by_uri(self, dids):
        dids.set_did("rAlice", uri="test")
        resolved = dids.resolve("did:nxf:rAlice")
        assert resolved is not None
        assert resolved.account == "rAlice"

    def test_resolve_invalid_uri(self, dids):
        assert dids.resolve("did:btc:xyz") is None

    def test_resolve_not_found(self, dids):
        assert dids.resolve("did:nxf:rNobody") is None


class TestDIDDocument:
    def test_to_dict(self, dids):
        ok, msg, did = dids.set_did("rAlice", uri="uri", data="data")
        d = did.to_dict()
        assert d["account"] == "rAlice"
        assert d["uri"] == "uri"
        assert d["data"] == "data"
