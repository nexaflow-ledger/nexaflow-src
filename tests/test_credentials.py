"""Tests for the credentials module."""

import pytest

from nexaflow_core.credentials import Credential, CredentialManager


@pytest.fixture
def creds():
    return CredentialManager()


class TestCredentialCreate:
    def test_create_credential(self, creds):
        ok, msg, cred = creds.create("rIssuer", "rSubject", "KYC",
                                      uri="https://example.com/kyc")
        assert ok is True
        assert cred is not None
        assert cred.issuer == "rIssuer"
        assert cred.subject == "rSubject"
        assert cred.credential_type == "KYC"
        assert cred.uri == "https://example.com/kyc"
        assert cred.accepted is False

    def test_create_self_issue_fails(self, creds):
        ok, msg, cred = creds.create("rSame", "rSame", "KYC")
        assert ok is False

    def test_create_different_types(self, creds):
        ok1, _, c1 = creds.create("rIssuer", "rSubject", "KYC")
        ok2, _, c2 = creds.create("rIssuer", "rSubject", "AML")
        assert ok1 is True
        assert ok2 is True
        assert c1.credential_id != c2.credential_id


class TestCredentialAccept:
    def test_accept_credential(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC")
        ok2, msg2 = creds.accept("rSubject", cred.credential_id)
        assert ok2 is True
        assert cred.accepted is True

    def test_accept_by_wrong_subject(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC")
        ok2, msg2 = creds.accept("rWrong", cred.credential_id)
        assert ok2 is False

    def test_accept_nonexistent(self, creds):
        ok, msg = creds.accept("rSubject", "bad-id")
        assert ok is False


class TestCredentialDelete:
    def test_delete_by_issuer(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC")
        ok2, msg2 = creds.delete("rIssuer", cred.credential_id)
        assert ok2 is True

    def test_delete_by_subject(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC")
        ok2, msg2 = creds.delete("rSubject", cred.credential_id)
        assert ok2 is True

    def test_delete_unauthorized(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC")
        ok2, msg2 = creds.delete("rRandom", cred.credential_id)
        assert ok2 is False


class TestCredentialCheck:
    def test_check_accepted(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC")
        creds.accept("rSubject", cred.credential_id)
        assert creds.check_credential("rIssuer", "rSubject", "KYC") is True

    def test_check_not_accepted(self, creds):
        creds.create("rIssuer", "rSubject", "KYC")
        assert creds.check_credential("rIssuer", "rSubject", "KYC") is False

    def test_check_nonexistent(self, creds):
        assert creds.check_credential("rIssuer", "rSubject", "KYC") is False


class TestCredentialQuery:
    def test_get_by_issuer(self, creds):
        creds.create("rIssuer", "rS1", "KYC")
        creds.create("rIssuer", "rS2", "KYC")
        issued = creds.get_by_issuer("rIssuer")
        assert len(issued) == 2

    def test_get_by_subject(self, creds):
        creds.create("rI1", "rSubject", "KYC")
        creds.create("rI2", "rSubject", "AML")
        received = creds.get_by_subject("rSubject")
        assert len(received) == 2


class TestCredentialDict:
    def test_to_dict(self, creds):
        ok, _, cred = creds.create("rIssuer", "rSubject", "KYC",
                                    uri="https://ex.com")
        d = cred.to_dict()
        assert d["issuer"] == "rIssuer"
        assert d["subject"] == "rSubject"
        assert d["credential_type"] == "KYC"
        assert "credential_id" in d
