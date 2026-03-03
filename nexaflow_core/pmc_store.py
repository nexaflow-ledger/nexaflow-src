"""
LMDB-backed persistent storage for PMC (Programmable Micro Coin) state.

Replaces the purely-in-RAM approach so that all PMC state — coin
definitions, holder balances, DEX offers, PoW chains, commitments,
and difficulty epochs — survives node restarts without requiring a
full P2P re-sync.

Architecture:
    - Uses **LMDB** (Lightning Memory-Mapped Database), the same engine
      used by Monero, for crash-safe, zero-copy reads and ACID writes.
    - Separate *named databases* (LMDB sub-databases) act like RocksDB
      column families — one per data type for clean prefix-free iteration.
    - Keys are UTF-8 strings; values are compact JSON bytes.
    - Composite keys use ``':'`` as separator (e.g. ``coin_id:account``).
    - Batch writes are atomic: all-or-nothing via LMDB write transactions.

Usage:
    store = PMCStore("data/pmc.lmdb")
    store.put_coin(coin_id, coin_dict)
    coin = store.get_coin(coin_id)
    store.close()
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("nexaflow_pmc_store")

# Sentinel for missing values
_MISSING = object()

# Composite-key separator (must not appear in coin_ids, accounts, etc.)
SEP = ":"


def _encode_key(key: str) -> bytes:
    return key.encode("utf-8")


def _encode_value(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _decode_value(raw: bytes) -> Any:
    return json.loads(raw)


def _composite(*parts: str) -> bytes:
    return SEP.join(parts).encode("utf-8")


class PMCStore:
    """
    LMDB-backed key-value store for the PMC sub-system.

    Each data category lives in its own LMDB named database (sub-db)
    for clean isolation and efficient iteration.
    """

    # Named databases (column families)
    _DB_NAMES: list[bytes] = [
        b"coins",        # coin_id → PMCDefinition dict
        b"holders",      # coin_id:account → PMCHolder dict
        b"offers",       # offer_id → PMCOffer dict
        b"pow_hashes",   # coin_id → last PoW hash (str)
        b"pending_txs",  # coin_id → JSON list of pending tx dicts
        b"commitments",  # coin_id:index → PMCCommitment dict
        b"tx_commit_idx",# tx_hash → commitment_id (str)
        b"epoch_history", # coin_id:epoch_number → DifficultyEpoch dict
        b"symbol_idx",   # symbol → coin_id
        b"issuer_idx",   # issuer → JSON list of coin_ids
        b"offer_idx",    # coin_id → JSON list of offer_ids
        b"meta",         # arbitrary key → value (seq counters, etc.)
    ]

    # Default map size: 1 GiB — LMDB will not use this much physical
    # space; it just reserves virtual address space.  The OS lazily
    # allocates pages as data is written.  Safe to set high.
    DEFAULT_MAP_SIZE = 1 << 30  # 1 GiB

    def __init__(
        self,
        path: str = "data/pmc.lmdb",
        map_size: int = DEFAULT_MAP_SIZE,
        readonly: bool = False,
    ):
        import lmdb

        self.path = path
        Path(path).mkdir(parents=True, exist_ok=True)
        self._env = lmdb.open(
            path,
            max_dbs=len(self._DB_NAMES) + 2,
            map_size=map_size,
            readonly=readonly,
            # LMDB default: sync on commit for durability
            metasync=True,
            sync=True,
            # Allow multiple readers (default)
            max_readers=126,
            # Don't lock in readonly mode (allows concurrent readers)
            lock=not readonly,
        )
        # Open all named sub-databases
        self._dbs: dict[bytes, Any] = {}
        for name in self._DB_NAMES:
            self._dbs[name] = self._env.open_db(name)

        logger.info(f"PMCStore opened: {path} (map_size={map_size >> 20} MiB)")

    # ── Lifecycle ────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the LMDB environment."""
        if self._env is not None:
            self._env.close()
            self._env = None  # type: ignore[assignment]
            logger.info("PMCStore closed")

    def sync(self) -> None:
        """Force an fsync to disk."""
        if self._env is not None:
            self._env.sync(True)

    @property
    def is_open(self) -> bool:
        return self._env is not None

    # ── Internal helpers ─────────────────────────────────────────────

    def _get(self, db_name: bytes, key: str | bytes) -> Any | None:
        """Read a single value. Returns None if not found."""
        db = self._dbs[db_name]
        k = key if isinstance(key, bytes) else _encode_key(key)
        with self._env.begin(db=db) as txn:
            raw = txn.get(k)
        return _decode_value(raw) if raw is not None else None

    def _put(self, db_name: bytes, key: str | bytes, value: Any) -> None:
        """Write a single value."""
        db = self._dbs[db_name]
        k = key if isinstance(key, bytes) else _encode_key(key)
        v = _encode_value(value)
        with self._env.begin(write=True, db=db) as txn:
            txn.put(k, v)

    def _delete(self, db_name: bytes, key: str | bytes) -> bool:
        """Delete a single key. Returns True if the key existed."""
        db = self._dbs[db_name]
        k = key if isinstance(key, bytes) else _encode_key(key)
        with self._env.begin(write=True, db=db) as txn:
            return txn.delete(k)

    def _iterate(self, db_name: bytes, prefix: bytes | None = None) -> list[tuple[bytes, Any]]:
        """Iterate over a named database, optionally filtering by key prefix."""
        db = self._dbs[db_name]
        results: list[tuple[bytes, Any]] = []
        with self._env.begin(db=db) as txn:
            cursor = txn.cursor()
            if prefix is not None:
                if not cursor.set_range(prefix):
                    return results
                for k, v in cursor:
                    if not k.startswith(prefix):
                        break
                    results.append((k, _decode_value(v)))
            else:
                for k, v in cursor:
                    results.append((k, _decode_value(v)))
        return results

    def _count(self, db_name: bytes) -> int:
        """Count entries in a named database."""
        db = self._dbs[db_name]
        with self._env.begin(db=db) as txn:
            return txn.stat()["entries"]

    # ── Batch write (atomic multi-key writes) ────────────────────────

    def batch_write(self, operations: list[tuple[bytes, str | bytes, Any | None]]) -> None:
        """
        Atomic batch write across multiple named databases.

        Each operation is a tuple: (db_name, key, value).
        If *value* is ``None``, the key is deleted; otherwise it's a put.

        All operations succeed or fail atomically.
        """
        with self._env.begin(write=True) as txn:
            for db_name, key, value in operations:
                db = self._dbs[db_name]
                k = key if isinstance(key, bytes) else _encode_key(key)
                if value is None:
                    txn.delete(k, db=db)
                else:
                    txn.put(k, _encode_value(value), db=db)

    # ═══════════════════════════════════════════════════════════════
    #  Coin definitions
    # ═══════════════════════════════════════════════════════════════

    def put_coin(self, coin_id: str, coin_dict: dict) -> None:
        self._put(b"coins", coin_id, coin_dict)

    def get_coin(self, coin_id: str) -> dict | None:
        return self._get(b"coins", coin_id)

    def delete_coin(self, coin_id: str) -> bool:
        return self._delete(b"coins", coin_id)

    def list_coins(self) -> list[tuple[str, dict]]:
        return [(k.decode(), v) for k, v in self._iterate(b"coins")]

    def coin_count(self) -> int:
        return self._count(b"coins")

    # ═══════════════════════════════════════════════════════════════
    #  Holder balances
    # ═══════════════════════════════════════════════════════════════

    def put_holder(self, coin_id: str, account: str, holder_dict: dict) -> None:
        key = _composite(coin_id, account)
        self._put(b"holders", key, holder_dict)

    def get_holder(self, coin_id: str, account: str) -> dict | None:
        key = _composite(coin_id, account)
        return self._get(b"holders", key)

    def delete_holder(self, coin_id: str, account: str) -> bool:
        key = _composite(coin_id, account)
        return self._delete(b"holders", key)

    def list_holders(self, coin_id: str) -> list[tuple[str, dict]]:
        """All holders for a given coin."""
        prefix = _composite(coin_id, "")  # "coin_id:"
        results = self._iterate(b"holders", prefix)
        # Strip the coin_id prefix from the key to return just the account
        prefix_len = len(prefix)
        return [(k[prefix_len:].decode(), v) for k, v in results]

    def holder_count(self, coin_id: str | None = None) -> int:
        if coin_id is None:
            return self._count(b"holders")
        return len(self.list_holders(coin_id))

    # ═══════════════════════════════════════════════════════════════
    #  DEX offers
    # ═══════════════════════════════════════════════════════════════

    def put_offer(self, offer_id: str, offer_dict: dict) -> None:
        self._put(b"offers", offer_id, offer_dict)

    def get_offer(self, offer_id: str) -> dict | None:
        return self._get(b"offers", offer_id)

    def delete_offer(self, offer_id: str) -> bool:
        return self._delete(b"offers", offer_id)

    def list_offers(self) -> list[tuple[str, dict]]:
        return [(k.decode(), v) for k, v in self._iterate(b"offers")]

    # ═══════════════════════════════════════════════════════════════
    #  PoW chain hashes
    # ═══════════════════════════════════════════════════════════════

    def put_pow_hash(self, coin_id: str, hash_val: str) -> None:
        self._put(b"pow_hashes", coin_id, hash_val)

    def get_pow_hash(self, coin_id: str) -> str | None:
        return self._get(b"pow_hashes", coin_id)

    def list_pow_hashes(self) -> dict[str, str]:
        return {k.decode(): v for k, v in self._iterate(b"pow_hashes")}

    # ═══════════════════════════════════════════════════════════════
    #  Pending transaction pools
    # ═══════════════════════════════════════════════════════════════

    def put_pending_txs(self, coin_id: str, pool: list[dict]) -> None:
        """Store the entire pending pool for a coin as a single value."""
        self._put(b"pending_txs", coin_id, pool)

    def get_pending_txs(self, coin_id: str) -> list[dict]:
        val = self._get(b"pending_txs", coin_id)
        return val if val is not None else []

    def clear_pending_txs(self, coin_id: str) -> None:
        self._delete(b"pending_txs", coin_id)

    def list_all_pending_txs(self) -> dict[str, list[dict]]:
        return {k.decode(): v for k, v in self._iterate(b"pending_txs")}

    # ═══════════════════════════════════════════════════════════════
    #  Commitment history
    # ═══════════════════════════════════════════════════════════════

    def put_commitment(self, coin_id: str, index: int, commit_dict: dict) -> None:
        """Store a single commitment at a specific index in the chain."""
        key = _composite(coin_id, str(index).zfill(10))
        self._put(b"commitments", key, commit_dict)

    def get_commitment(self, coin_id: str, index: int) -> dict | None:
        key = _composite(coin_id, str(index).zfill(10))
        return self._get(b"commitments", key)

    def list_commitments(self, coin_id: str) -> list[dict]:
        """All commitments for a coin, in order."""
        prefix = _composite(coin_id, "")
        results = self._iterate(b"commitments", prefix)
        return [v for _, v in results]

    def commitment_count(self, coin_id: str | None = None) -> int:
        if coin_id is None:
            return self._count(b"commitments")
        return len(self.list_commitments(coin_id))

    # ═══════════════════════════════════════════════════════════════
    #  Tx → commitment index
    # ═══════════════════════════════════════════════════════════════

    def put_tx_commit_idx(self, tx_hash: str, commitment_id: str) -> None:
        self._put(b"tx_commit_idx", tx_hash, commitment_id)

    def get_tx_commit_idx(self, tx_hash: str) -> str | None:
        return self._get(b"tx_commit_idx", tx_hash)

    def list_tx_commit_idx(self) -> dict[str, str]:
        return {k.decode(): v for k, v in self._iterate(b"tx_commit_idx")}

    # ═══════════════════════════════════════════════════════════════
    #  Difficulty epoch history
    # ═══════════════════════════════════════════════════════════════

    def put_epoch(self, coin_id: str, epoch_number: int, epoch_dict: dict) -> None:
        key = _composite(coin_id, str(epoch_number).zfill(10))
        self._put(b"epoch_history", key, epoch_dict)

    def get_epoch(self, coin_id: str, epoch_number: int) -> dict | None:
        key = _composite(coin_id, str(epoch_number).zfill(10))
        return self._get(b"epoch_history", key)

    def list_epochs(self, coin_id: str) -> list[dict]:
        prefix = _composite(coin_id, "")
        results = self._iterate(b"epoch_history", prefix)
        return [v for _, v in results]

    # ═══════════════════════════════════════════════════════════════
    #  Symbol index
    # ═══════════════════════════════════════════════════════════════

    def put_symbol(self, symbol: str, coin_id: str) -> None:
        self._put(b"symbol_idx", symbol, coin_id)

    def get_symbol(self, symbol: str) -> str | None:
        return self._get(b"symbol_idx", symbol)

    def delete_symbol(self, symbol: str) -> bool:
        return self._delete(b"symbol_idx", symbol)

    def list_symbols(self) -> dict[str, str]:
        return {k.decode(): v for k, v in self._iterate(b"symbol_idx")}

    # ═══════════════════════════════════════════════════════════════
    #  Issuer index
    # ═══════════════════════════════════════════════════════════════

    def put_issuer_coins(self, issuer: str, coin_ids: list[str]) -> None:
        self._put(b"issuer_idx", issuer, coin_ids)

    def get_issuer_coins(self, issuer: str) -> list[str]:
        val = self._get(b"issuer_idx", issuer)
        return val if val is not None else []

    def list_issuers(self) -> dict[str, list[str]]:
        return {k.decode(): v for k, v in self._iterate(b"issuer_idx")}

    # ═══════════════════════════════════════════════════════════════
    #  Offer index
    # ═══════════════════════════════════════════════════════════════

    def put_offer_index(self, coin_id: str, offer_ids: list[str]) -> None:
        self._put(b"offer_idx", coin_id, offer_ids)

    def get_offer_index(self, coin_id: str) -> list[str]:
        val = self._get(b"offer_idx", coin_id)
        return val if val is not None else []

    def list_offer_indices(self) -> dict[str, list[str]]:
        return {k.decode(): v for k, v in self._iterate(b"offer_idx")}

    # ═══════════════════════════════════════════════════════════════
    #  Meta (sequences, counters)
    # ═══════════════════════════════════════════════════════════════

    def put_meta(self, key: str, value: Any) -> None:
        self._put(b"meta", key, value)

    def get_meta(self, key: str, default: Any = None) -> Any:
        val = self._get(b"meta", key)
        return val if val is not None else default

    def list_meta(self) -> dict[str, Any]:
        return {k.decode(): v for k, v in self._iterate(b"meta")}

    # ═══════════════════════════════════════════════════════════════
    #  Bulk import / export (for sync integration)
    # ═══════════════════════════════════════════════════════════════

    def export_all(self) -> dict[str, Any]:
        """
        Export the entire PMC store as a JSON-serialisable dict.

        This is used by the sync protocol to build snapshots from
        disk-backed state without needing to load everything into RAM.
        """
        return {
            "coins": dict(self.list_coins()),
            "holders": self._export_holders(),
            "offers": dict(self.list_offers()),
            "pow_hashes": self.list_pow_hashes(),
            "pending_txs": self.list_all_pending_txs(),
            "commitments": self._export_commitments(),
            "tx_commit_index": self.list_tx_commit_idx(),
            "epoch_history": self._export_epochs(),
            "symbol_index": self.list_symbols(),
            "issuer_index": self.list_issuers(),
            "offer_index": self.list_offer_indices(),
            "seq": self._export_seq(),
            "offer_seq": self.get_meta("offer_seq", 0),
        }

    def _export_holders(self) -> dict[str, dict[str, dict]]:
        """Group holders by coin_id for sync-compatible format."""
        raw = self._iterate(b"holders")
        result: dict[str, dict[str, dict]] = {}
        for k, v in raw:
            key_str = k.decode()
            sep_idx = key_str.index(SEP)
            coin_id = key_str[:sep_idx]
            account = key_str[sep_idx + 1:]
            result.setdefault(coin_id, {})[account] = v
        return result

    def _export_commitments(self) -> dict[str, list[dict]]:
        """Group commitments by coin_id for sync-compatible format."""
        raw = self._iterate(b"commitments")
        result: dict[str, list[dict]] = {}
        for k, v in raw:
            key_str = k.decode()
            sep_idx = key_str.index(SEP)
            coin_id = key_str[:sep_idx]
            result.setdefault(coin_id, []).append(v)
        return result

    def _export_epochs(self) -> dict[str, list[dict]]:
        """Group epoch history by coin_id for sync-compatible format."""
        raw = self._iterate(b"epoch_history")
        result: dict[str, list[dict]] = {}
        for k, v in raw:
            key_str = k.decode()
            sep_idx = key_str.index(SEP)
            coin_id = key_str[:sep_idx]
            result.setdefault(coin_id, []).append(v)
        return result

    def _export_seq(self) -> dict[str, int]:
        """Export issuer sequence counters from meta."""
        meta = self.list_meta()
        return {
            k[len("seq:"):]: v
            for k, v in meta.items()
            if k.startswith("seq:")
        }

    def import_all(self, data: dict[str, Any]) -> None:
        """
        Bulk-import PMC state from a serialised dict (e.g. from a sync
        snapshot).  This replaces ALL existing data atomically.

        Uses a single LMDB write transaction for atomicity — the import
        either fully succeeds or fully rolls back.
        """
        ops: list[tuple[bytes, str | bytes, Any | None]] = []

        # Coins
        for cid, cd in data.get("coins", {}).items():
            ops.append((b"coins", cid, cd))

        # Holders (nested: coin_id → account → dict)
        for cid, acct_map in data.get("holders", {}).items():
            for acct, hd in acct_map.items():
                ops.append((b"holders", _composite(cid, acct), hd))

        # Offers
        for oid, od in data.get("offers", {}).items():
            ops.append((b"offers", oid, od))

        # PoW hashes
        for cid, h in data.get("pow_hashes", {}).items():
            ops.append((b"pow_hashes", cid, h))

        # Pending txs
        for cid, pool in data.get("pending_txs", {}).items():
            ops.append((b"pending_txs", cid, pool))

        # Commitments (nested: coin_id → [commit_dicts])
        for cid, chain in data.get("commitments", {}).items():
            for idx, cd in enumerate(chain):
                key = _composite(cid, str(idx).zfill(10))
                ops.append((b"commitments", key, cd))

        # Tx commit index
        for txh, commit_id in data.get("tx_commit_index", {}).items():
            ops.append((b"tx_commit_idx", txh, commit_id))

        # Epoch history (nested: coin_id → [epoch_dicts])
        for cid, epochs in data.get("epoch_history", {}).items():
            for ed in epochs:
                epoch_num = ed.get("epoch_number", 0)
                key = _composite(cid, str(epoch_num).zfill(10))
                ops.append((b"epoch_history", key, ed))

        # Symbol index
        for sym, cid in data.get("symbol_index", {}).items():
            ops.append((b"symbol_idx", sym, cid))

        # Issuer index
        for issuer, cids in data.get("issuer_index", {}).items():
            ops.append((b"issuer_idx", issuer, cids))

        # Offer index
        for cid, oids in data.get("offer_index", {}).items():
            ops.append((b"offer_idx", cid, oids))

        # Sequences
        for issuer, seq_val in data.get("seq", {}).items():
            ops.append((b"meta", f"seq:{issuer}", seq_val))

        # Offer sequence
        if "offer_seq" in data:
            ops.append((b"meta", "offer_seq", data["offer_seq"]))

        self.batch_write(ops)
        logger.info(
            f"PMCStore bulk import: {len(data.get('coins', {}))} coins, "
            f"{sum(len(v) for v in data.get('holders', {}).values())} holders, "
            f"{len(ops)} total operations"
        )

    def clear_all(self) -> None:
        """Wipe every named database. Use with caution."""
        with self._env.begin(write=True) as txn:
            for db_name in self._DB_NAMES:
                db = self._dbs[db_name]
                txn.drop(db, delete=False)  # clear entries, keep db
        logger.info("PMCStore cleared all databases")

    # ═══════════════════════════════════════════════════════════════
    #  Stats / diagnostics
    # ═══════════════════════════════════════════════════════════════

    def stats(self) -> dict[str, Any]:
        """Return per-database entry counts and LMDB env info."""
        env_stat = self._env.stat()
        env_info = self._env.info()
        db_counts = {}
        for name in self._DB_NAMES:
            db = self._dbs[name]
            with self._env.begin(db=db) as txn:
                db_counts[name.decode()] = txn.stat()["entries"]
        return {
            "path": self.path,
            "map_size_mb": env_info["map_size"] >> 20,
            "page_size": env_stat["psize"],
            "entries_total": sum(db_counts.values()),
            "databases": db_counts,
        }

    def __repr__(self) -> str:
        total = sum(
            self._count(name) for name in self._DB_NAMES
        ) if self._env else 0
        return f"<PMCStore path={self.path!r} entries={total}>"

    def __del__(self) -> None:
        if hasattr(self, "_env") and self._env is not None:
            try:
                self.close()
            except Exception:
                pass
