"""
SHAMap — Merkle hash-tree for ledger state (Tier 3).

Provides a deterministic SHA-512-Half-based Merkle trie that stores
all ledger objects (accounts, trust lines, offers, escrows, etc.)
so any node can prove inclusion or exclusion with a compact proof.

Keylets
-------
Each ledger object type has a deterministic 256-bit key computed from
the object type and its identifying fields.  These keys are the leaf
addresses in the SHAMap.

    keylet = SHA-512-Half(SPACE_TYPE || field1 || field2 || ...)

Object types map to space bytes so that different object categories
never collide in the trie.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


# ── Keylet space bytes (one per ledger object type) ─────────────

class LedgerSpace(IntEnum):
    ACCOUNT     = 0x61   # 'a'
    TRUST_LINE  = 0x72   # 'r'
    OFFER       = 0x6F   # 'o'
    ESCROW      = 0x75   # 'u'
    CHECK       = 0x43   # 'C'
    PAY_CHANNEL = 0x78   # 'x'
    NFTOKEN     = 0x4E   # 'N'
    NFTOKEN_OFFER = 0x51 # 'Q'
    TICKET      = 0x54   # 'T'
    SIGNER_LIST = 0x53   # 'S'
    AMM         = 0x41   # 'A'
    ORACLE      = 0x52   # 'R'
    DID         = 0x44   # 'D'
    MPT         = 0x7E   # '~'
    CREDENTIAL  = 0x64   # 'd'
    BRIDGE      = 0x42   # 'B'
    HOOK        = 0x48   # 'H'
    AMENDMENT   = 0x66   # 'f'
    FEE         = 0x65   # 'e'
    NEGATIVE_UNL = 0x4C  # 'L'


# ── Hash helpers ────────────────────────────────────────────────

def sha512_half(data: bytes) -> bytes:
    """SHA-512 first-256 bits (32 bytes) — the same as rippled."""
    return hashlib.sha512(data).digest()[:32]


def compute_keylet(space: int, *parts: bytes | str) -> bytes:
    """Compute a 32-byte keylet from a space byte and component fields."""
    buf = struct.pack(">B", space)
    for p in parts:
        if isinstance(p, str):
            p = p.encode("utf-8")
        buf += p
    return sha512_half(buf)


# ── Convenience keylet constructors ─────────────────────────────

def account_keylet(address: str) -> bytes:
    return compute_keylet(LedgerSpace.ACCOUNT, address)


def trust_line_keylet(holder: str, currency: str, issuer: str) -> bytes:
    return compute_keylet(LedgerSpace.TRUST_LINE, holder, currency, issuer)


def offer_keylet(account: str, sequence: int) -> bytes:
    return compute_keylet(LedgerSpace.OFFER, account, struct.pack(">q", sequence))


def escrow_keylet(account: str, escrow_id: str) -> bytes:
    return compute_keylet(LedgerSpace.ESCROW, account, escrow_id)


def check_keylet(check_id: str) -> bytes:
    return compute_keylet(LedgerSpace.CHECK, check_id)


def pay_channel_keylet(channel_id: str) -> bytes:
    return compute_keylet(LedgerSpace.PAY_CHANNEL, channel_id)


def nftoken_keylet(nftoken_id: str) -> bytes:
    return compute_keylet(LedgerSpace.NFTOKEN, nftoken_id)


def ticket_keylet(account: str, ticket_seq: int) -> bytes:
    return compute_keylet(LedgerSpace.TICKET, account, struct.pack(">q", ticket_seq))


def amm_keylet(pool_id: str) -> bytes:
    return compute_keylet(LedgerSpace.AMM, pool_id)


def oracle_keylet(owner: str, document_id: int) -> bytes:
    return compute_keylet(LedgerSpace.ORACLE, owner, struct.pack(">q", document_id))


def did_keylet(account: str) -> bytes:
    return compute_keylet(LedgerSpace.DID, account)


def mpt_keylet(issuance_id: str) -> bytes:
    return compute_keylet(LedgerSpace.MPT, issuance_id)


def credential_keylet(credential_id: str) -> bytes:
    return compute_keylet(LedgerSpace.CREDENTIAL, credential_id)


def bridge_keylet(bridge_id: str) -> bytes:
    return compute_keylet(LedgerSpace.BRIDGE, bridge_id)


def hook_keylet(account: str, position: int) -> bytes:
    return compute_keylet(LedgerSpace.HOOK, account, struct.pack(">i", position))


# ── SHAMap Node types ───────────────────────────────────────────

EMPTY_HASH = b"\x00" * 32
BRANCH_FACTOR = 16   # each inner node has 16 children (hex nibble)


@dataclass
class SHAMapLeaf:
    """A leaf storing an object's serialised data and its keylet."""
    key: bytes              # 32-byte keylet
    data: bytes             # serialised object value
    object_type: int = 0    # LedgerSpace enum value

    @property
    def hash(self) -> bytes:
        return sha512_half(self.key + self.data)


@dataclass
class SHAMapInner:
    """An inner (branch) node with up to 16 children."""
    children: list[SHAMapInner | SHAMapLeaf | None] = field(
        default_factory=lambda: [None] * BRANCH_FACTOR
    )
    _cached_hash: bytes = field(default=b"", repr=False)

    @property
    def hash(self) -> bytes:
        if self._cached_hash:
            return self._cached_hash
        buf = b""
        for child in self.children:
            if child is None:
                buf += EMPTY_HASH
            else:
                buf += child.hash
        self._cached_hash = sha512_half(buf)
        return self._cached_hash

    def invalidate(self) -> None:
        """Invalidate cached hash up through this node."""
        self._cached_hash = b""


# ── Merkle proof ────────────────────────────────────────────────

@dataclass
class MerkleProof:
    """Proof of inclusion/exclusion for a key in the SHAMap."""
    key: bytes
    leaf_data: bytes | None      # None = exclusion proof
    path: list[tuple[int, list[bytes]]]  # (branch_index, sibling_hashes)
    root_hash: bytes

    def verify(self) -> bool:
        """Verify the proof against the stored root hash."""
        if self.leaf_data is not None:
            current = sha512_half(self.key + self.leaf_data)
        else:
            current = EMPTY_HASH

        for branch_idx, siblings in reversed(self.path):
            buf = b""
            placed = False
            si = 0
            for i in range(BRANCH_FACTOR):
                if i == branch_idx:
                    buf += current
                    placed = True
                else:
                    buf += siblings[si] if si < len(siblings) else EMPTY_HASH
                    si += 1
            current = sha512_half(buf)

        return current == self.root_hash


# ── SHAMap ──────────────────────────────────────────────────────

class SHAMap:
    """
    SHA-512-Half Merkle trie for ledger state.

    Keys are 32-byte keylets; values are arbitrary byte strings.
    The trie is indexed by the hex nibbles of the key.
    """

    def __init__(self):
        self.root = SHAMapInner()
        self._count = 0

    @property
    def size(self) -> int:
        return self._count

    @property
    def root_hash(self) -> bytes:
        return self.root.hash

    def insert(self, key: bytes, data: bytes, object_type: int = 0) -> None:
        """Insert or update a leaf."""
        nibbles = _key_to_nibbles(key)
        node = self.root
        parents: list[SHAMapInner] = [self.root]

        for depth in range(len(nibbles) - 1):
            idx = nibbles[depth]
            child = node.children[idx]
            if child is None:
                # Empty slot — place leaf here
                node.children[idx] = SHAMapLeaf(key, data, object_type)
                self._count += 1
                _invalidate_path(parents)
                return
            elif isinstance(child, SHAMapLeaf):
                if child.key == key:
                    # Update existing leaf
                    child.data = data
                    _invalidate_path(parents)
                    return
                # Collision — split into inner node
                new_inner = SHAMapInner()
                existing_nibbles = _key_to_nibbles(child.key)
                new_idx = existing_nibbles[depth + 1] if depth + 1 < len(existing_nibbles) else 0
                new_inner.children[new_idx] = child
                node.children[idx] = new_inner
                node = new_inner
                parents.append(node)
                continue
            else:
                # Inner node — descend
                node = child
                parents.append(node)

        # Place at final depth
        idx = nibbles[-1]
        existing = node.children[idx]
        if existing is None:
            self._count += 1
        node.children[idx] = SHAMapLeaf(key, data, object_type)
        _invalidate_path(parents)

    def get(self, key: bytes) -> bytes | None:
        """Retrieve data for a key, or None if not found."""
        nibbles = _key_to_nibbles(key)
        node = self.root
        for depth in range(len(nibbles)):
            idx = nibbles[depth]
            child = node.children[idx]
            if child is None:
                return None
            elif isinstance(child, SHAMapLeaf):
                return child.data if child.key == key else None
            else:
                node = child
        return None

    def remove(self, key: bytes) -> bool:
        """Remove a leaf by key. Returns True if found and removed."""
        nibbles = _key_to_nibbles(key)
        node = self.root
        parents: list[tuple[SHAMapInner, int]] = []

        for depth in range(len(nibbles)):
            idx = nibbles[depth]
            child = node.children[idx]
            if child is None:
                return False
            elif isinstance(child, SHAMapLeaf):
                if child.key != key:
                    return False
                node.children[idx] = None
                self._count -= 1
                _invalidate_path([p for p, _ in parents] + [node])
                return True
            else:
                parents.append((node, idx))
                node = child
        return False

    def get_proof(self, key: bytes) -> MerkleProof:
        """Generate a Merkle inclusion/exclusion proof for a key."""
        nibbles = _key_to_nibbles(key)
        node = self.root
        path: list[tuple[int, list[bytes]]] = []
        leaf_data = None

        for depth in range(len(nibbles)):
            idx = nibbles[depth]
            siblings = []
            for i in range(BRANCH_FACTOR):
                if i != idx:
                    child = node.children[i]
                    siblings.append(child.hash if child else EMPTY_HASH)
            path.append((idx, siblings))

            child = node.children[idx]
            if child is None:
                break
            elif isinstance(child, SHAMapLeaf):
                if child.key == key:
                    leaf_data = child.data
                break
            else:
                node = child

        return MerkleProof(
            key=key,
            leaf_data=leaf_data,
            path=path,
            root_hash=self.root_hash,
        )

    def all_leaves(self) -> list[SHAMapLeaf]:
        """Return all leaves in the trie."""
        result: list[SHAMapLeaf] = []
        _collect_leaves(self.root, result)
        return result


# ── Internal helpers ────────────────────────────────────────────

def _key_to_nibbles(key: bytes) -> list[int]:
    """Convert a 32-byte key to a list of hex nibbles (0-15)."""
    nibbles = []
    for b in key:
        nibbles.append((b >> 4) & 0x0F)
        nibbles.append(b & 0x0F)
    return nibbles


def _invalidate_path(nodes: list[SHAMapInner]) -> None:
    """Invalidate cached hashes along a path from leaf to root."""
    for node in nodes:
        if isinstance(node, SHAMapInner):
            node.invalidate()


def _collect_leaves(node: SHAMapInner | SHAMapLeaf | None,
                    result: list[SHAMapLeaf]) -> None:
    """Recursively collect all leaves."""
    if node is None:
        return
    if isinstance(node, SHAMapLeaf):
        result.append(node)
        return
    for child in node.children:
        _collect_leaves(child, result)
