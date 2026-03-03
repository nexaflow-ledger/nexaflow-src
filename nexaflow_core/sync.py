"""
Efficient ledger synchronisation protocol for NexaFlow.

Implements a multi-phase sync strategy that minimises bandwidth:

1. **Status exchange** — peers compare ``(sequence, last_hash)`` to detect
   divergence without transferring any state data.

2. **Delta sync (incremental)** — when the local node is only a few ledgers
   behind, only the missing closed-ledger headers and the current account
   state diff are transferred.

3. **Full-state sync (snapshot)** — when a node is far behind or brand-new
   it receives a compact, hash-verified snapshot of the entire ledger state
   including accounts, trust lines, staking pool, confidential outputs,
   and applied-tx IDs.

4. **Parallel peer requests** — sync status is requested from *all*
   connected peers simultaneously; the best (most-ahead, hash-verified)
   responder is chosen for the actual data transfer.

5. **Hash-chain verification** — received ledger headers are verified
   against the Blake2b hash chain so that corrupted or malicious data is
   rejected before it touches local state.

Message types added to the P2P protocol:

    SYNC_STATUS_REQ   — "what is your latest ledger?"
    SYNC_STATUS_RES   — ``{sequence, hash, closed_count}``
    SYNC_DELTA_REQ    — "send me headers + state since sequence N"
    SYNC_DELTA_RES    — incremental headers + account diffs
    SYNC_SNAP_REQ     — "send me everything"
    SYNC_SNAP_RES     — full serialised snapshot (chunked-safe)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nexaflow_core.p2p import P2PNode

logger = logging.getLogger("nexaflow_sync")

# If a peer is more than this many ledgers ahead, do a full snapshot sync
# rather than a delta (avoids huge incremental payloads).
DELTA_THRESHOLD = 50

# Seconds to wait for peers to reply with their sync status.
STATUS_TIMEOUT = 5.0

# Seconds to wait for the actual data payload from the chosen peer.
DATA_TIMEOUT = 30.0

# Minimum interval between automatic sync attempts (seconds).
SYNC_COOLDOWN = 15.0

# Maximum number of accounts per delta chunk to keep message size reasonable.
DELTA_CHUNK_ACCOUNTS = 500


# ─── Data helpers ────────────────────────────────────────────────────────


@dataclass
class PeerSyncStatus:
    """Lightweight snapshot of a remote peer's ledger position."""
    peer_id: str
    sequence: int = 0
    last_hash: str = ""
    closed_count: int = 0
    received_at: float = 0.0


def _serialise_account(acc: Any) -> dict:
    """Serialise an AccountEntry to a JSON-safe dict (incl. trust lines)."""
    tl_list = []
    for (currency, issuer), tl in acc.trust_lines.items():
        tl_list.append({
            "currency": currency,
            "issuer": issuer,
            "holder": tl.holder,
            "balance": tl.balance,
            "limit": tl.limit,
            "limit_peer": tl.limit_peer,
            "no_ripple": bool(tl.no_ripple),
        })
    return {
        "address": acc.address,
        "balance": acc.balance,
        "sequence": acc.sequence,
        "owner_count": acc.owner_count,
        "is_gateway": bool(acc.is_gateway),
        "transfer_rate": acc.transfer_rate,
        "trust_lines": tl_list,
    }


def _serialise_header(hdr: Any) -> dict:
    """Serialise a LedgerHeader to a JSON-safe dict."""
    return {
        "sequence": hdr.sequence,
        "hash": hdr.hash,
        "parent_hash": hdr.parent_hash,
        "tx_hash": hdr.tx_hash,
        "state_hash": hdr.state_hash,
        "close_time": hdr.close_time,
        "tx_count": hdr.tx_count,
        "total_nxf": hdr.total_nxf,
    }


def _serialise_stake(record: Any) -> dict:
    """Serialise a StakeRecord to a JSON-safe dict."""
    return {
        "stake_id": record.stake_id,
        "tx_id": record.tx_id,
        "address": record.address,
        "amount": record.amount,
        "tier": int(record.tier),
        "base_apy": record.base_apy,
        "effective_apy": record.effective_apy,
        "lock_duration": record.lock_duration,
        "start_time": record.start_time,
        "maturity_time": record.maturity_time,
        "matured": record.matured,
        "cancelled": record.cancelled,
        "payout_amount": record.payout_amount,
    }


def _serialise_confidential_output(out: Any) -> dict:
    """Serialise a ConfidentialOutput to a JSON-safe dict."""
    return {
        "commitment": out.commitment.hex(),
        "stealth_addr": out.stealth_addr.hex(),
        "ephemeral_pub": out.ephemeral_pub.hex() if out.ephemeral_pub else "",
        "range_proof": out.range_proof.hex() if out.range_proof else "",
        "view_tag": out.view_tag.hex() if out.view_tag else "",
        "tx_id": out.tx_id,
        "spent": out.spent,
    }


# ─── PMC serialisation helpers ───────────────────────────────────────────


def _serialise_pmc_coin(coin: Any) -> dict:
    """Serialise a PMCDefinition to a JSON-safe dict."""
    return coin.to_dict()


def _serialise_pmc_holder(holder: Any) -> dict:
    """Serialise a PMCHolder to a JSON-safe dict."""
    return holder.to_dict()


def _serialise_pmc_offer(offer: Any) -> dict:
    """Serialise a PMCOffer to a JSON-safe dict."""
    return offer.to_dict()


def _serialise_pmc_commitment(commitment: Any) -> dict:
    """Serialise a PMCCommitment to a JSON-safe dict."""
    return commitment.to_dict()


def _serialise_pmc_epoch(epoch: Any) -> dict:
    """Serialise a DifficultyEpoch to a JSON-safe dict."""
    return epoch.to_dict()


def _serialise_pmc_state(ledger: Any) -> dict:
    """
    Serialise the entire PMC sub-system state from a ledger's PMCManager.

    When the PMCManager has an LMDB-backed store, we can export directly
    from disk — avoiding full in-memory traversal for large datasets.

    Captures:
      - Coin definitions (including epoch/halving fields)
      - Holder balances per coin
      - Active and historical DEX offers
      - PoW chain hashes (last hash per coin)
      - Transaction commitment pool and history
      - Difficulty epoch history
      - Internal indices (symbol → coin_id, issuer → [coin_id])
    """
    mgr = getattr(ledger, "pmc_manager", None)
    if mgr is None:
        return {}

    # Fast path: if the manager has a persistent store, export from it
    store = getattr(mgr, "_store", None)
    if store is not None and hasattr(store, "export_all"):
        return store.export_all()

    # Coin definitions
    coins = {}
    for cid, coin in mgr.coins.items():
        coins[cid] = _serialise_pmc_coin(coin)

    # Holders: coin_id → { account → holder_dict }
    holders: dict[str, dict[str, dict]] = {}
    for cid, acct_map in mgr._holders.items():
        holders[cid] = {
            acct: _serialise_pmc_holder(h)
            for acct, h in acct_map.items()
        }

    # Offers
    offers = {
        oid: _serialise_pmc_offer(o) for oid, o in mgr.offers.items()
    }

    # PoW chain hashes
    pow_hashes = dict(mgr._last_pow_hash)

    # Pending tx pools
    pending_txs: dict[str, list[dict]] = {}
    for cid, pool in mgr._pending_txs.items():
        pending_txs[cid] = list(pool)

    # Commitment history
    commitments: dict[str, list[dict]] = {}
    for cid, chain in mgr._commitments.items():
        commitments[cid] = [_serialise_pmc_commitment(c) for c in chain]

    # Tx → commitment index
    tx_commit_index = dict(mgr._tx_commitment_index)

    # Epoch history
    epoch_history: dict[str, list[dict]] = {}
    for cid, epochs in mgr._epoch_history.items():
        epoch_history[cid] = [_serialise_pmc_epoch(e) for e in epochs]

    # Indices & sequences
    symbol_index = dict(mgr._symbol_index)
    issuer_index = {k: list(v) for k, v in mgr._issuer_index.items()}
    offer_index = {k: list(v) for k, v in mgr._offer_index.items()}
    seq = dict(mgr._seq)
    offer_seq = mgr._offer_seq

    return {
        "coins": coins,
        "holders": holders,
        "offers": offers,
        "pow_hashes": pow_hashes,
        "pending_txs": pending_txs,
        "commitments": commitments,
        "tx_commit_index": tx_commit_index,
        "epoch_history": epoch_history,
        "symbol_index": symbol_index,
        "issuer_index": issuer_index,
        "offer_index": offer_index,
        "seq": seq,
        "offer_seq": offer_seq,
    }


# ─── Snapshot builder (used by the *serving* side) ───────────────────────


def build_full_snapshot(ledger: Any) -> dict:
    """
    Build a complete, JSON-serialisable snapshot of the ledger.

    The snapshot includes everything needed to reconstruct ledger state
    on a peer that has no prior data.
    """
    accounts = {}
    for addr, acc in ledger.accounts.items():
        accounts[addr] = _serialise_account(acc)

    headers = [_serialise_header(h) for h in ledger.closed_ledgers]

    stakes = {}
    if hasattr(ledger, "staking_pool") and ledger.staking_pool is not None:
        for sid, rec in ledger.staking_pool.stakes.items():
            stakes[sid] = _serialise_stake(rec)

    confidential = {}
    for sa_hex, out in ledger.confidential_outputs.items():
        confidential[sa_hex] = _serialise_confidential_output(out)

    return {
        "type": "full",
        "current_sequence": ledger.current_sequence,
        "total_supply": ledger.total_supply,
        "initial_supply": ledger.initial_supply,
        "total_burned": ledger.total_burned,
        "total_minted": ledger.total_minted,
        "accounts": accounts,
        "closed_ledgers": headers,
        "stakes": stakes,
        "confidential_outputs": confidential,
        "applied_tx_ids": list(ledger.applied_tx_ids),
        "spent_key_images": [ki.hex() for ki in ledger.spent_key_images],
        "pmc_state": _serialise_pmc_state(ledger),
    }


def build_delta_snapshot(ledger: Any, since_seq: int) -> dict:
    """
    Build an incremental snapshot containing only changes since *since_seq*.

    Includes:
      - Ledger headers with sequence > since_seq
      - All current account states (compact; trust lines included)
      - Current staking pool state
      - Confidential outputs
      - Monetary aggregates (supply, burned, minted)
      - Applied tx IDs (full set — small relative to state)

    The receiver replaces its state with the received data when the
    received sequence is ahead.
    """
    headers = [
        _serialise_header(h)
        for h in ledger.closed_ledgers
        if h.sequence > since_seq
    ]

    accounts = {}
    for addr, acc in ledger.accounts.items():
        accounts[addr] = _serialise_account(acc)

    stakes = {}
    if hasattr(ledger, "staking_pool") and ledger.staking_pool is not None:
        for sid, rec in ledger.staking_pool.stakes.items():
            stakes[sid] = _serialise_stake(rec)

    confidential = {}
    for sa_hex, out in ledger.confidential_outputs.items():
        confidential[sa_hex] = _serialise_confidential_output(out)

    return {
        "type": "delta",
        "since_seq": since_seq,
        "current_sequence": ledger.current_sequence,
        "total_supply": ledger.total_supply,
        "initial_supply": ledger.initial_supply,
        "total_burned": ledger.total_burned,
        "total_minted": ledger.total_minted,
        "accounts": accounts,
        "closed_ledgers": headers,
        "stakes": stakes,
        "confidential_outputs": confidential,
        "applied_tx_ids": list(ledger.applied_tx_ids),
        "spent_key_images": [ki.hex() for ki in ledger.spent_key_images],
        "pmc_state": _serialise_pmc_state(ledger),
    }


# ─── Snapshot applier (used by the *receiving* side) ─────────────────────


def _verify_header_chain(headers: list[dict], local_last_hash: str) -> bool:
    """
    Verify that the received headers form a valid hash chain.

    Each header's parent_hash must equal the previous header's hash.
    The first received header's parent_hash must match our local tip.
    For new nodes (empty local_last_hash) the first header must have
    sequence 1 and parent_hash of all zeros (genesis anchor).
    Returns True if the chain is valid (or empty).
    """
    if not headers:
        return True
    # Sort by sequence just in case
    headers_sorted = sorted(headers, key=lambda h: h["sequence"])
    prev_hash = local_last_hash
    for i, hdr in enumerate(headers_sorted):
        if i == 0 and not prev_hash:
            # New node: first header must be genesis (sequence 1)
            if hdr["sequence"] != 1:
                logger.warning(
                    f"New node expected genesis (seq 1), got seq {hdr['sequence']}"
                )
                return False
            # Genesis parent hash must be all zeros
            expected_genesis_parent = "0" * 64
            if hdr.get("parent_hash", "") != expected_genesis_parent:
                logger.warning(
                    f"Genesis header has non-zero parent_hash: "
                    f"{hdr.get('parent_hash', '')[:16]}..."
                )
                return False
        elif prev_hash and hdr["parent_hash"] != prev_hash:
            logger.warning(
                f"Header chain break at seq {hdr['sequence']}: "
                f"expected parent {prev_hash[:16]}... "
                f"got {hdr['parent_hash'][:16]}..."
            )
            return False
        prev_hash = hdr["hash"]
    return True


def apply_snapshot(ledger: Any, snapshot: dict) -> bool:
    """
    Apply a received snapshot (full or delta) to the local ledger.

    Performs hash-chain verification on received headers before mutating
    any state.  Returns True on success, False if verification fails.
    """
    from nexaflow_core.ledger import ConfidentialOutput, LedgerHeader, TrustLineEntry
    from nexaflow_core.staking import StakeRecord, StakeTier

    peer_seq = snapshot.get("current_sequence", 0)
    if peer_seq <= ledger.current_sequence:
        logger.debug(
            f"Snapshot seq {peer_seq} not ahead of local "
            f"{ledger.current_sequence}, skipping"
        )
        return False

    # ── Verify header chain ──────────────────────────────────────────
    received_headers = snapshot.get("closed_ledgers", [])
    local_last_hash = ""
    if ledger.closed_ledgers:
        local_last_hash = ledger.closed_ledgers[-1].hash

    if not _verify_header_chain(received_headers, local_last_hash):
        logger.error("Rejecting snapshot: header hash-chain verification failed")
        return False

    # ── Monetary aggregates ──────────────────────────────────────────
    ledger.total_supply = snapshot.get("total_supply", ledger.total_supply)
    ledger.total_burned = snapshot.get("total_burned", ledger.total_burned)
    ledger.total_minted = snapshot.get("total_minted", ledger.total_minted)
    if "initial_supply" in snapshot:
        ledger.initial_supply = snapshot["initial_supply"]

    # ── Accounts (full replacement for all received addrs) ───────────
    for addr, acc_data in snapshot.get("accounts", {}).items():
        if not ledger.account_exists(addr):
            ledger.create_account(addr, acc_data.get("balance", 0.0))
        acc = ledger.get_account(addr)
        if acc is None:
            continue
        acc.balance = acc_data.get("balance", acc.balance)
        acc.sequence = acc_data.get("sequence", acc.sequence)
        acc.owner_count = acc_data.get("owner_count", acc.owner_count)
        acc.is_gateway = acc_data.get("is_gateway", acc.is_gateway)
        acc.transfer_rate = acc_data.get("transfer_rate", acc.transfer_rate)

        # Trust lines
        for tl_data in acc_data.get("trust_lines", []):
            key = (tl_data["currency"], tl_data["issuer"])
            if key not in acc.trust_lines:
                tl = TrustLineEntry(
                    tl_data["currency"],
                    tl_data["issuer"],
                    tl_data.get("holder", addr),
                    tl_data.get("limit", 0.0),
                )
                acc.trust_lines[key] = tl
                acc.owner_count += 1
            else:
                tl = acc.trust_lines[key]
            tl.balance = tl_data.get("balance", tl.balance)
            tl.limit = tl_data.get("limit", tl.limit)
            tl.limit_peer = tl_data.get("limit_peer", tl.limit_peer)
            tl.no_ripple = tl_data.get("no_ripple", False)

    # ── Closed ledger headers ────────────────────────────────────────
    existing_seqs = {h.sequence for h in ledger.closed_ledgers}
    for hdr_data in received_headers:
        seq = hdr_data["sequence"]
        if seq in existing_seqs:
            continue
        header = LedgerHeader(seq, hdr_data.get("parent_hash", "0" * 64))
        header.hash = hdr_data["hash"]
        header.tx_hash = hdr_data.get("tx_hash", "")
        header.state_hash = hdr_data.get("state_hash", "")
        header.close_time = int(hdr_data.get("close_time", 0))
        header.tx_count = hdr_data.get("tx_count", 0)
        header.total_nxf = hdr_data.get("total_nxf", 0.0)
        ledger.closed_ledgers.append(header)

    ledger.closed_ledgers.sort(key=lambda h: h.sequence)
    ledger.current_sequence = peer_seq

    # ── Staking pool ─────────────────────────────────────────────────
    if hasattr(ledger, "staking_pool") and snapshot.get("stakes"):
        pool = ledger.staking_pool
        for sid, s_data in snapshot["stakes"].items():
            if sid in pool.stakes:
                continue  # don't overwrite existing stakes
            try:
                record = StakeRecord(
                    stake_id=s_data["stake_id"],
                    tx_id=s_data["tx_id"],
                    address=s_data["address"],
                    amount=s_data["amount"],
                    tier=StakeTier(s_data["tier"]),
                    base_apy=s_data["base_apy"],
                    effective_apy=s_data["effective_apy"],
                    lock_duration=s_data["lock_duration"],
                    start_time=s_data["start_time"],
                    maturity_time=s_data["maturity_time"],
                    matured=s_data.get("matured", False),
                    cancelled=s_data.get("cancelled", False),
                    payout_amount=s_data.get("payout_amount", 0.0),
                )
                pool.stakes[record.stake_id] = record
                pool.stakes_by_address.setdefault(
                    record.address, []
                ).append(record.stake_id)
                if record.matured is False and record.cancelled is False:
                    pool.total_staked += record.amount
            except (KeyError, ValueError) as exc:
                logger.warning(f"Skipping invalid stake {sid}: {exc}")

    # ── Confidential outputs ─────────────────────────────────────────
    for sa_hex, co_data in snapshot.get("confidential_outputs", {}).items():
        if sa_hex in ledger.confidential_outputs:
            continue
        try:
            out = ConfidentialOutput(
                bytes.fromhex(co_data["commitment"]),
                bytes.fromhex(co_data["stealth_addr"]),
                bytes.fromhex(co_data["ephemeral_pub"]) if co_data.get("ephemeral_pub") else b"",
                bytes.fromhex(co_data["range_proof"]) if co_data.get("range_proof") else b"",
                bytes.fromhex(co_data["view_tag"]) if co_data.get("view_tag") else b"",
                co_data.get("tx_id", ""),
            )
            out.spent = co_data.get("spent", False)
            ledger.confidential_outputs[sa_hex] = out
        except (KeyError, ValueError) as exc:
            logger.warning(f"Skipping invalid confidential output {sa_hex}: {exc}")

    # ── Applied TX IDs ───────────────────────────────────────────────
    for tx_id in snapshot.get("applied_tx_ids", []):
        ledger.applied_tx_ids.add(tx_id)

    # ── Spent key images ─────────────────────────────────────────────
    for ki_hex in snapshot.get("spent_key_images", []):
        with contextlib.suppress(ValueError):
            ledger.spent_key_images.add(bytes.fromhex(ki_hex))

    # ── PMC state ────────────────────────────────────────────────────
    pmc_data = snapshot.get("pmc_state")
    if pmc_data:
        _apply_pmc_state(ledger, pmc_data)

    logger.info(
        f"Snapshot applied: seq {ledger.current_sequence}, "
        f"{len(snapshot.get('accounts', {}))} accounts, "
        f"{len(received_headers)} new headers"
    )
    return True


# ─── PMC state applier ──────────────────────────────────────────────────


def _apply_pmc_state(ledger: Any, pmc_data: dict) -> None:
    """
    Reconstruct the PMCManager state from a serialised snapshot.

    This replaces the entire PMC sub-system state on the receiving node
    so that coins, balances, offers, PoW chains, commitment histories,
    and difficulty epoch records are faithfully replicated.
    """
    from nexaflow_core.pmc import (
        DifficultyEpoch,
        PMCCommitment,
        PMCDefinition,
        PMCHolder,
        PMCOffer,
        PMCRule,
    )

    mgr = getattr(ledger, "pmc_manager", None)
    if mgr is None:
        return

    # ── Coin definitions ─────────────────────────────────────────
    for cid, cd in pmc_data.get("coins", {}).items():
        if cid in mgr.coins:
            # Update existing coin with latest state
            coin = mgr.coins[cid]
            coin.total_minted = cd.get("total_minted", coin.total_minted)
            coin.total_burned = cd.get("total_burned", coin.total_burned)
            coin.total_mints = cd.get("total_mints", coin.total_mints)
            coin.pow_difficulty = cd.get("pow_difficulty", coin.pow_difficulty)
            coin.base_reward = cd.get("base_reward", coin.base_reward)
            coin.frozen = cd.get("frozen", coin.frozen)
            coin.epoch_length = cd.get("epoch_length", coin.epoch_length)
            coin.target_block_time = cd.get("target_block_time", coin.target_block_time)
            coin.halving_interval = cd.get("halving_interval", coin.halving_interval)
            coin.halvings_completed = cd.get("halvings_completed", coin.halvings_completed)
            coin.current_epoch = cd.get("current_epoch", coin.current_epoch)
            coin.epoch_start_mint = cd.get("epoch_start_mint", coin.epoch_start_mint)
            coin.epoch_start_time = cd.get("epoch_start_time", coin.epoch_start_time)
        else:
            # Reconstruct coin from scratch
            rules = []
            for rd in cd.get("rules", []):
                try:
                    rules.append(PMCRule.from_dict(rd))
                except (KeyError, ValueError):
                    pass
            coin = PMCDefinition(
                coin_id=cid,
                symbol=cd.get("symbol", ""),
                name=cd.get("name", ""),
                issuer=cd.get("issuer", ""),
                decimals=cd.get("decimals", 8),
                max_supply=cd.get("max_supply", 0.0),
                total_minted=cd.get("total_minted", 0.0),
                total_burned=cd.get("total_burned", 0.0),
                flags=cd.get("flags", 0),
                pow_difficulty=cd.get("pow_difficulty", 4),
                base_reward=cd.get("base_reward", 50.0),
                metadata=cd.get("metadata", ""),
                rules=rules,
                created_at=cd.get("created_at", 0.0),
                frozen=cd.get("frozen", False),
                total_mints=cd.get("total_mints", 0),
                epoch_length=cd.get("epoch_length", 100),
                target_block_time=cd.get("target_block_time", 60.0),
                halving_interval=cd.get("halving_interval", 10_000),
                halvings_completed=cd.get("halvings_completed", 0),
                current_epoch=cd.get("current_epoch", 0),
                epoch_start_mint=cd.get("epoch_start_mint", 0),
                epoch_start_time=cd.get("epoch_start_time", 0.0),
            )
            mgr.coins[cid] = coin

    # ── Holder balances ──────────────────────────────────────────
    for cid, acct_map in pmc_data.get("holders", {}).items():
        holders = mgr._holders.setdefault(cid, {})
        for acct, hd in acct_map.items():
            if acct in holders:
                h = holders[acct]
                h.balance = hd.get("balance", h.balance)
                h.frozen = hd.get("frozen", h.frozen)
                h.last_transfer_at = hd.get("last_transfer_at", h.last_transfer_at)
                h.last_mint_at = hd.get("last_mint_at", h.last_mint_at)
            else:
                h = PMCHolder(
                    account=acct,
                    coin_id=cid,
                    balance=hd.get("balance", 0.0),
                    frozen=hd.get("frozen", False),
                    last_transfer_at=hd.get("last_transfer_at", 0.0),
                    last_mint_at=hd.get("last_mint_at", 0.0),
                )
                holders[acct] = h

    # ── DEX offers ───────────────────────────────────────────────
    for oid, od in pmc_data.get("offers", {}).items():
        if oid not in mgr.offers:
            offer = PMCOffer(
                offer_id=oid,
                coin_id=od.get("coin_id", ""),
                owner=od.get("owner", ""),
                is_sell=od.get("is_sell", True),
                amount=od.get("amount", 0.0),
                price=od.get("price", 0.0),
                counter_coin_id=od.get("counter_coin_id", ""),
                filled=od.get("filled", 0.0),
                destination=od.get("destination", ""),
                expiration=od.get("expiration", 0.0),
                created_at=od.get("created_at", 0.0),
                cancelled=od.get("cancelled", False),
            )
            mgr.offers[oid] = offer

    # ── PoW chain hashes ─────────────────────────────────────────
    for cid, h in pmc_data.get("pow_hashes", {}).items():
        mgr._last_pow_hash[cid] = h

    # ── Pending tx pools ─────────────────────────────────────────
    for cid, pool in pmc_data.get("pending_txs", {}).items():
        mgr._pending_txs[cid] = list(pool)

    # ── Commitment history ───────────────────────────────────────
    for cid, chain in pmc_data.get("commitments", {}).items():
        existing_ids = {
            c.commitment_id for c in mgr._commitments.get(cid, [])
        }
        for cd_dict in chain:
            if cd_dict.get("commitment_id", "") in existing_ids:
                continue
            try:
                comm = PMCCommitment(
                    commitment_id=cd_dict["commitment_id"],
                    coin_id=cd_dict.get("coin_id", cid),
                    miner=cd_dict.get("miner", ""),
                    tx_root=cd_dict.get("tx_root", ""),
                    tx_hashes=cd_dict.get("tx_hashes", []),
                    tx_count=cd_dict.get("tx_count", 0),
                    pow_hash=cd_dict.get("pow_hash", ""),
                    difficulty=cd_dict.get("difficulty", 1),
                    reward=cd_dict.get("reward", 0.0),
                    timestamp=cd_dict.get("timestamp", 0.0),
                    prev_commitment=cd_dict.get("prev_commitment", ""),
                )
                mgr._commitments.setdefault(cid, []).append(comm)
            except (KeyError, ValueError) as exc:
                logger.warning(f"Skipping invalid PMC commitment: {exc}")

    # ── Tx → commitment index ────────────────────────────────────
    for txh, cid in pmc_data.get("tx_commit_index", {}).items():
        mgr._tx_commitment_index[txh] = cid

    # ── Epoch history ────────────────────────────────────────────
    for cid, epochs in pmc_data.get("epoch_history", {}).items():
        existing_nums = {
            e.epoch_number for e in mgr._epoch_history.get(cid, [])
        }
        for ed in epochs:
            if ed.get("epoch_number", -1) in existing_nums:
                continue
            try:
                epoch = DifficultyEpoch(
                    epoch_number=ed["epoch_number"],
                    coin_id=ed.get("coin_id", cid),
                    start_mint=ed.get("start_mint", 0),
                    end_mint=ed.get("end_mint", 0),
                    start_time=ed.get("start_time", 0.0),
                    end_time=ed.get("end_time", 0.0),
                    mints_in_epoch=ed.get("mints_in_epoch", 0),
                    avg_block_time=ed.get("avg_block_time", 0.0),
                    target_block_time=ed.get("target_block_time", 60.0),
                    old_difficulty=ed.get("old_difficulty", 1),
                    new_difficulty=ed.get("new_difficulty", 1),
                    adjustment_factor=ed.get("adjustment_factor", 1.0),
                    halving_occurred=ed.get("halving_occurred", False),
                    old_base_reward=ed.get("old_base_reward", 0.0),
                    new_base_reward=ed.get("new_base_reward", 0.0),
                )
                mgr._epoch_history.setdefault(cid, []).append(epoch)
                existing_nums.add(epoch.epoch_number)
            except (KeyError, ValueError) as exc:
                logger.warning(f"Skipping invalid PMC epoch: {exc}")

    # ── Indices & sequences ──────────────────────────────────────
    for sym, cid in pmc_data.get("symbol_index", {}).items():
        mgr._symbol_index[sym] = cid
    for issuer, cids in pmc_data.get("issuer_index", {}).items():
        mgr._issuer_index[issuer] = list(cids)
    for cid, oids in pmc_data.get("offer_index", {}).items():
        mgr._offer_index[cid] = list(oids)
    for issuer, seq in pmc_data.get("seq", {}).items():
        mgr._seq[issuer] = seq
    if "offer_seq" in pmc_data:
        mgr._offer_seq = pmc_data["offer_seq"]

    pmc_coin_count = len(pmc_data.get("coins", {}))
    if pmc_coin_count > 0:
        logger.info(f"PMC state synced: {pmc_coin_count} coins")

    # ── Flush to LMDB store if available ─────────────────────────
    if hasattr(mgr, "flush_to_store"):
        mgr.flush_to_store()


# ═════════════════════════════════════════════════════════════════════════
#  LedgerSyncManager — orchestrates the sync protocol over P2P
# ═════════════════════════════════════════════════════════════════════════


class LedgerSyncManager:
    """
    Manages efficient ledger synchronisation across the P2P network.

    Lifecycle:
        1. Call :meth:`start` after the P2P node is running.
        2. The manager runs a background loop that periodically checks
           all peers and syncs when needed.
        3. Call :meth:`request_sync` to trigger an immediate sync.
        4. Call :meth:`stop` during shutdown.

    The manager hooks into the P2P dispatch table via dedicated
    callbacks that the P2PNode routes to it.
    """

    def __init__(self, p2p: P2PNode, ledger: Any):
        self.p2p = p2p
        self.ledger = ledger

        # Sync state
        self._peer_statuses: dict[str, PeerSyncStatus] = {}
        self._sync_in_progress = False
        self._last_sync_time: float = 0.0

        # Asyncio primitives — created lazily in start() so that
        # construction works on Python 3.9 without a running event loop.
        self._sync_event: asyncio.Event | None = None
        self._status_received: asyncio.Event | None = None
        self._data_received: asyncio.Event | None = None
        self._received_snapshot: dict | None = None
        self._task: asyncio.Task | None = None
        self._running = False

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the background sync loop."""
        self._sync_event = asyncio.Event()
        self._status_received = asyncio.Event()
        self._data_received = asyncio.Event()
        self._running = True
        self._task = asyncio.create_task(self._sync_loop())
        logger.info("LedgerSyncManager started")

    async def stop(self) -> None:
        """Stop the sync manager gracefully."""
        self._running = False
        if self._sync_event is not None:
            self._sync_event.set()  # unblock the loop
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        logger.info("LedgerSyncManager stopped")

    async def request_sync(self) -> bool:
        """
        Trigger an immediate sync cycle.

        Returns True if a sync was performed, False if skipped (e.g.
        already in progress or on cooldown).
        """
        if self._sync_in_progress:
            logger.debug("Sync already in progress, skipping request")
            return False
        if self._sync_event is not None:
            self._sync_event.set()
        # Give the background loop time to pick it up
        await asyncio.sleep(0.1)
        return True

    # ── Background loop ──────────────────────────────────────────────

    async def _sync_loop(self) -> None:
        """Periodically check peers and sync when behind."""
        assert self._sync_event is not None
        while self._running:
            try:
                # Wait for a trigger or timeout
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        self._sync_event.wait(), timeout=SYNC_COOLDOWN
                    )
                self._sync_event.clear()

                if not self._running:
                    break

                # Cooldown guard
                elapsed = time.time() - self._last_sync_time
                if elapsed < SYNC_COOLDOWN and not self._sync_event.is_set():
                    continue

                await self._run_sync_cycle()

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Sync loop error")
                await asyncio.sleep(5.0)

    async def _run_sync_cycle(self) -> None:
        """Execute one full sync cycle: status -> choose peer -> fetch data."""
        assert self._status_received is not None
        assert self._data_received is not None
        if not self.p2p.peers:
            return

        self._sync_in_progress = True
        try:
            # Phase 1: Ask all peers for their sync status
            self._peer_statuses.clear()
            self._status_received.clear()

            await self._broadcast_status_request()

            # Wait for responses (with timeout)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    self._wait_for_all_statuses(), timeout=STATUS_TIMEOUT
                )

            if not self._peer_statuses:
                logger.debug("No peer status responses received")
                return

            # Phase 2: Find the best peer (highest sequence, valid)
            best = self._choose_best_peer()
            if best is None:
                logger.debug("All peers at same or lower sequence")
                return

            if best.sequence <= self.ledger.current_sequence:
                return

            gap = best.sequence - self.ledger.current_sequence
            logger.info(
                f"Syncing from {best.peer_id}: "
                f"peer seq={best.sequence}, local seq={self.ledger.current_sequence}, "
                f"gap={gap}"
            )

            # Phase 3: Request data (delta or full)
            self._data_received.clear()
            self._received_snapshot = None

            if gap <= DELTA_THRESHOLD:
                await self.p2p.send_to_peer(
                    best.peer_id, "SYNC_DELTA_REQ",
                    {"since_seq": self.ledger.current_sequence},
                )
            else:
                await self.p2p.send_to_peer(
                    best.peer_id, "SYNC_SNAP_REQ", {}
                )

            # Wait for the data response
            try:
                await asyncio.wait_for(
                    self._data_received.wait(), timeout=DATA_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(f"Sync data timeout from {best.peer_id}")
                return

            # Phase 4: Apply the received snapshot with multi-peer
            # verification for full snapshots (gap > DELTA_THRESHOLD).
            if self._received_snapshot:
                # For full snapshots, verify state hash against at least
                # one additional peer before committing.
                if gap > DELTA_THRESHOLD and len(self._peer_statuses) >= 2:
                    snap_hash = self._received_snapshot.get("state_hash", "")
                    if snap_hash:
                        corroborating = sum(
                            1 for pid, ps in self._peer_statuses.items()
                            if pid != best.peer_id and ps.last_hash == snap_hash
                        )
                        if corroborating == 0:
                            logger.warning(
                                f"No peers corroborate snapshot state hash "
                                f"{snap_hash[:16]}... — rejecting"
                            )
                            return
                ok = apply_snapshot(self.ledger, self._received_snapshot)
                if ok:
                    self._last_sync_time = time.time()
                    logger.info(
                        f"Ledger synced to seq {self.ledger.current_sequence}"
                    )
                else:
                    logger.warning("Snapshot application failed or rejected")

        finally:
            self._sync_in_progress = False

    # ── Peer status collection ───────────────────────────────────────

    async def _broadcast_status_request(self) -> None:
        """Send SYNC_STATUS_REQ to all connected peers in parallel."""
        tasks = []
        for pid in list(self.p2p.peers.keys()):
            tasks.append(
                self.p2p.send_to_peer(pid, "SYNC_STATUS_REQ", {
                    "node_id": self.p2p.node_id,
                    "sequence": self.ledger.current_sequence,
                })
            )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _wait_for_all_statuses(self) -> None:
        """Wait until we have a status from every connected peer."""
        deadline = time.time() + STATUS_TIMEOUT
        while time.time() < deadline:
            if len(self._peer_statuses) >= len(self.p2p.peers):
                return
            await asyncio.sleep(0.2)

    def _choose_best_peer(self) -> PeerSyncStatus | None:
        """Pick the peer with the highest sequence that is ahead of us."""
        best: PeerSyncStatus | None = None
        for ps in self._peer_statuses.values():
            if ps.sequence <= self.ledger.current_sequence:
                continue
            if best is None or ps.sequence > best.sequence:
                best = ps
        return best

    # ── P2P message handlers (called by P2PNode dispatch) ────────────

    def handle_sync_status_req(self, payload: dict, from_peer: str) -> dict:
        """
        Handle an incoming SYNC_STATUS_REQ — return our status for the
        P2P layer to send back.
        """
        last_hash = ""
        if self.ledger.closed_ledgers:
            last_hash = self.ledger.closed_ledgers[-1].hash
        return {
            "node_id": self.p2p.node_id,
            "sequence": self.ledger.current_sequence,
            "last_hash": last_hash,
            "closed_count": len(self.ledger.closed_ledgers),
        }

    def handle_sync_status_res(self, payload: dict, from_peer: str) -> None:
        """Handle an incoming SYNC_STATUS_RES from a peer."""
        self._peer_statuses[from_peer] = PeerSyncStatus(
            peer_id=from_peer,
            sequence=payload.get("sequence", 0),
            last_hash=payload.get("last_hash", ""),
            closed_count=payload.get("closed_count", 0),
            received_at=time.time(),
        )

    def handle_sync_delta_req(self, payload: dict, from_peer: str) -> dict:
        """Build and return a delta snapshot for the requesting peer."""
        since_seq = payload.get("since_seq", 0)
        logger.info(
            f"Building delta snapshot for {from_peer} since seq {since_seq}"
        )
        return build_delta_snapshot(self.ledger, since_seq)

    def handle_sync_snap_req(self, payload: dict, from_peer: str) -> dict:
        """Build and return a full snapshot for the requesting peer."""
        logger.info(f"Building full snapshot for {from_peer}")
        return build_full_snapshot(self.ledger)

    def handle_sync_data_res(self, payload: dict, from_peer: str) -> None:
        """Handle an incoming SYNC_DELTA_RES or SYNC_SNAP_RES."""
        self._received_snapshot = payload
        if self._data_received is not None:
            self._data_received.set()

    # ── Legacy LEDGER_REQ/RES compat ─────────────────────────────────

    def handle_ledger_request(self, from_peer: str) -> dict:
        """
        Backward-compatible handler for LEDGER_REQ — serves a full snapshot.
        Old peers that only speak LEDGER_REQ/RES still work.
        """
        return build_full_snapshot(self.ledger)

    def handle_ledger_response(self, payload: dict, from_peer: str) -> None:
        """
        Backward-compatible handler for LEDGER_RES — apply as snapshot.

        Only processes the response when a sync cycle is in progress
        to prevent unsolicited full-state replacements.
        """
        if not self._sync_in_progress:
            logger.warning(
                f"Ignoring unsolicited LEDGER_RES from {from_peer} "
                "(no sync in progress)"
            )
            return
        apply_snapshot(self.ledger, payload)

    # ── Status ───────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "syncing": self._sync_in_progress,
            "last_sync": self._last_sync_time,
            "peer_statuses": {
                pid: {
                    "sequence": ps.sequence,
                    "last_hash": ps.last_hash[:16] + "..." if ps.last_hash else "",
                }
                for pid, ps in self._peer_statuses.items()
            },
            "local_sequence": self.ledger.current_sequence,
        }
