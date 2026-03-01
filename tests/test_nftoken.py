"""
Test suite for nexaflow_core.nftoken — non-fungible tokens.

Covers:
  - NFToken minting (serial, ID, flags)
  - NFToken burning (owner, issuer, unauthorized)
  - NFTokenOffer create (buy/sell), validity, expiration
  - accept_offer (token transfer, destination restriction)
  - cancel_offer
  - Manager queries (get_tokens_for_account, get_offers_for_token)
  - Edge cases: burn already burned, sell non-owned, non-transferable
"""

import unittest

from nexaflow_core.nftoken import NFToken, NFTokenManager, NFTokenOffer


class TestNFToken(unittest.TestCase):

    def test_to_dict(self):
        t = NFToken(
            nftoken_id="tok1", issuer="rAlice", owner="rAlice",
            uri="ipfs://abc", transfer_fee=500, nftoken_taxon=1,
            transferable=True, burnable=True, serial=0,
        )
        d = t.to_dict()
        self.assertEqual(d["nftoken_id"], "tok1")
        self.assertEqual(d["transfer_fee"], 500)


class TestNFTokenOffer(unittest.TestCase):

    def test_is_valid_fresh(self):
        o = NFTokenOffer(
            offer_id="off1", nftoken_id="tok1", owner="rAlice",
            amount=10.0, destination="", is_sell=True, expiration=0,
        )
        self.assertTrue(o.is_valid(now=1_000_000.0))

    def test_is_valid_expired(self):
        o = NFTokenOffer(
            offer_id="off1", nftoken_id="tok1", owner="rAlice",
            amount=10.0, destination="", is_sell=True, expiration=1_000,
        )
        self.assertFalse(o.is_valid(now=2_000.0))

    def test_is_valid_accepted(self):
        o = NFTokenOffer(
            offer_id="off1", nftoken_id="tok1", owner="rAlice",
            amount=10.0, destination="", is_sell=True, expiration=0,
        )
        o.accepted = True
        self.assertFalse(o.is_valid())


class TestNFTokenManager(unittest.TestCase):

    def setUp(self):
        self.mgr = NFTokenManager()

    # ── mint ─────────────────────────────────────────────────────

    def test_mint_basic(self):
        t = self.mgr.mint("rAlice", uri="ipfs://abc", now=1000.0)
        self.assertEqual(t.issuer, "rAlice")
        self.assertEqual(t.owner, "rAlice")
        self.assertEqual(t.serial, 0)
        self.assertEqual(len(t.nftoken_id), 64)

    def test_mint_serial_increments(self):
        t1 = self.mgr.mint("rAlice", now=1000.0)
        t2 = self.mgr.mint("rAlice", now=1001.0)
        self.assertEqual(t1.serial, 0)
        self.assertEqual(t2.serial, 1)
        self.assertNotEqual(t1.nftoken_id, t2.nftoken_id)

    def test_mint_different_issuers_independent_serials(self):
        t1 = self.mgr.mint("rAlice", now=1000.0)
        t2 = self.mgr.mint("rBob", now=1001.0)
        self.assertEqual(t1.serial, 0)
        self.assertEqual(t2.serial, 0)

    def test_mint_invalid_transfer_fee(self):
        with self.assertRaises(ValueError):
            self.mgr.mint("rAlice", transfer_fee=-1)
        with self.assertRaises(ValueError):
            self.mgr.mint("rAlice", transfer_fee=50001)

    def test_mint_flags(self):
        t = self.mgr.mint("rAlice", transferable=False, burnable=False, now=1000.0)
        self.assertFalse(t.transferable)
        self.assertFalse(t.burnable)

    # ── burn ─────────────────────────────────────────────────────

    def test_burn_by_owner(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        result, err = self.mgr.burn(t.nftoken_id, "rAlice")
        self.assertEqual(err, "")
        self.assertTrue(result.burned)

    def test_burn_by_issuer_if_burnable(self):
        t = self.mgr.mint("rAlice", burnable=True, now=1000.0)
        # Transfer to rBob
        t.owner = "rBob"
        result, err = self.mgr.burn(t.nftoken_id, "rAlice")
        self.assertEqual(err, "")
        self.assertTrue(result.burned)

    def test_burn_by_issuer_not_burnable(self):
        t = self.mgr.mint("rAlice", burnable=False, now=1000.0)
        t.owner = "rBob"
        result, err = self.mgr.burn(t.nftoken_id, "rAlice")
        self.assertNotEqual(err, "")
        self.assertFalse(result.burned)

    def test_burn_unauthorized(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        result, err = self.mgr.burn(t.nftoken_id, "rBob")
        self.assertNotEqual(err, "")

    def test_burn_nonexistent(self):
        result, err = self.mgr.burn("nope", "rAlice")
        self.assertIsNone(result)
        self.assertIn("not found", err)

    def test_burn_already_burned(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.burn(t.nftoken_id, "rAlice")
        result, err = self.mgr.burn(t.nftoken_id, "rAlice")
        self.assertIn("Already burned", err)

    # ── create_offer ─────────────────────────────────────────────

    def test_sell_offer(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, err = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                            is_sell=True, now=1001.0)
        self.assertEqual(err, "")
        self.assertTrue(offer.is_sell)

    def test_sell_offer_non_owner_rejected(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, err = self.mgr.create_offer("o1", t.nftoken_id, "rBob", 50.0,
                                            is_sell=True, now=1001.0)
        self.assertIn("Only owner", err)

    def test_buy_own_token_rejected(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, err = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                            is_sell=False, now=1001.0)
        self.assertIn("Cannot buy", err)

    def test_buy_non_transferable_rejected(self):
        t = self.mgr.mint("rAlice", transferable=False, now=1000.0)
        offer, err = self.mgr.create_offer("o1", t.nftoken_id, "rBob", 50.0,
                                            is_sell=False, now=1001.0)
        self.assertIn("not transferable", err)

    def test_offer_burned_token(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.burn(t.nftoken_id, "rAlice")
        offer, err = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                            is_sell=True)
        self.assertIn("burned", err)

    # ── accept_offer ─────────────────────────────────────────────

    def test_accept_sell_offer(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, _ = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                          is_sell=True, now=1001.0)
        result, err = self.mgr.accept_offer("o1", "rBob", now=1002.0)
        self.assertEqual(err, "")
        self.assertEqual(t.owner, "rBob")
        self.assertTrue(result.accepted)

    def test_accept_buy_offer(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, _ = self.mgr.create_offer("o1", t.nftoken_id, "rBob", 50.0,
                                          is_sell=False, now=1001.0)
        # Owner (rAlice) accepts the buy offer
        result, err = self.mgr.accept_offer("o1", "rAlice", now=1002.0)
        self.assertEqual(err, "")
        self.assertEqual(t.owner, "rBob")

    def test_accept_buy_offer_non_owner_rejected(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, _ = self.mgr.create_offer("o1", t.nftoken_id, "rBob", 50.0,
                                          is_sell=False, now=1001.0)
        result, err = self.mgr.accept_offer("o1", "rCharlie", now=1002.0)
        self.assertIn("Only token owner", err)

    def test_accept_own_sell_offer_rejected(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, _ = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                          is_sell=True, now=1001.0)
        result, err = self.mgr.accept_offer("o1", "rAlice", now=1002.0)
        self.assertIn("Cannot accept own", err)

    def test_accept_expired_offer(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, _ = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                          is_sell=True, expiration=1500, now=1001.0)
        result, err = self.mgr.accept_offer("o1", "rBob", now=2000.0)
        self.assertIn("expired", err)

    def test_accept_restricted_destination(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        offer, _ = self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                                          destination="rBob", is_sell=True, now=1001.0)
        result, err = self.mgr.accept_offer("o1", "rCharlie", now=1002.0)
        self.assertIn("restricted", err)
        # rBob can accept
        result, err = self.mgr.accept_offer("o1", "rBob", now=1003.0)
        self.assertEqual(err, "")

    def test_accept_nonexistent_offer(self):
        result, err = self.mgr.accept_offer("nope", "rBob")
        self.assertIsNone(result)
        self.assertIn("not found", err)

    # ── cancel_offer ─────────────────────────────────────────────

    def test_cancel_own_offer(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                              is_sell=True, now=1001.0)
        result, err = self.mgr.cancel_offer("o1", "rAlice")
        self.assertEqual(err, "")
        self.assertTrue(result.cancelled)

    def test_cancel_others_offer_rejected(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                              is_sell=True, now=1001.0)
        result, err = self.mgr.cancel_offer("o1", "rBob")
        self.assertIn("Only offer creator", err)

    # ── queries ──────────────────────────────────────────────────

    def test_get_tokens_for_account(self):
        self.mgr.mint("rAlice", now=1000.0)
        self.mgr.mint("rAlice", now=1001.0)
        self.mgr.mint("rBob", now=1002.0)
        tokens = self.mgr.get_tokens_for_account("rAlice")
        self.assertEqual(len(tokens), 2)

    def test_get_tokens_excludes_burned(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.burn(t.nftoken_id, "rAlice")
        tokens = self.mgr.get_tokens_for_account("rAlice")
        self.assertEqual(len(tokens), 0)

    def test_get_offers_for_token(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                              is_sell=True, now=1001.0)
        self.mgr.create_offer("o2", t.nftoken_id, "rBob", 40.0,
                              is_sell=False, now=1002.0)
        offers = self.mgr.get_offers_for_token(t.nftoken_id)
        self.assertEqual(len(offers), 2)

    def test_get_offers_excludes_resolved(self):
        t = self.mgr.mint("rAlice", now=1000.0)
        self.mgr.create_offer("o1", t.nftoken_id, "rAlice", 50.0,
                              is_sell=True, now=1001.0)
        self.mgr.accept_offer("o1", "rBob", now=1002.0)
        offers = self.mgr.get_offers_for_token(t.nftoken_id)
        self.assertEqual(len(offers), 0)


if __name__ == "__main__":
    unittest.main()
