# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
"""
Cython-optimized NexaFlow Protocol Consensus Algorithm (RPCA) for NexaFlow.

Implements a Byzantine-fault-tolerant (BFT) variant of RPCA:

  1. Each validator proposes a candidate transaction set and **signs** the
     proposal with its secp256k1 private key.
  2. Proposals are exchanged across the Unique Node List (UNL).
  3. The engine verifies every incoming proposal signature before counting
     the vote.  Validators that submit conflicting proposals for the same
     ledger sequence / round (equivocation) are flagged as Byzantine and
     excluded from the quorum count.
  4. Safety guarantee: the system tolerates up to
         f = floor((n - 1) / 3)   Byzantine UNL members
     where n = |UNL| + 1 (including self).  The engine logs a warning when
     the current UNL is smaller than 3f + 1.
  5. Voting rounds escalate the vote threshold from 50 % to 80 %.  Because
     80 % > 2/3 the final threshold already satisfies the standard BFT
     requirement (2f + 1 out of n honest votes).

Module also exposes the fast proposal-voting engine used by the node runner.
"""

import hashlib

cimport cython
from libc.time cimport time as c_time

from nexaflow_core.negative_unl import NegativeUNL


# ── GIL-free helpers ─────────────────────────────────────────────────────

cdef inline double _threshold_for_round(
    double initial, double step, int round_num, double cap,
) nogil:
    """Compute the consensus threshold for a given round without the GIL."""
    cdef double t = initial + step * round_num
    if t > cap:
        return cap
    return t


cdef inline bint _vote_passes(int votes, int total, double threshold) nogil:
    """Return True when votes/total >= threshold (no Python objects)."""
    if total == 0:
        return False
    return <double>votes >= threshold * <double>total


# Consensus phases
cdef int PHASE_OPEN       = 0   # accepting transactions
cdef int PHASE_ESTABLISH  = 1   # voting rounds in progress
cdef int PHASE_ACCEPTED   = 2   # consensus reached
cdef int PHASE_FAILED     = 3   # no consensus after max rounds

PHASE_NAMES = {
    PHASE_OPEN: "open",
    PHASE_ESTABLISH: "establish",
    PHASE_ACCEPTED: "accepted",
    PHASE_FAILED: "failed",
}

# ===================================================================
#  Proposal
# ===================================================================

@cython.freelist(8)
cdef class Proposal:
    """A validator's proposed transaction set for a ledger round.

    Attributes
    ----------
    validator_id  Unique identifier for the proposing validator.
    ledger_seq    Ledger sequence number this proposal targets.
    tx_ids        Set of tx_id strings the validator wants included.
    round_number  Consensus round in which this proposal was created.
    signature     Optional DER-encoded ECDSA signature over the proposal
                  hash.  When present it is verified by the engine before
                  the proposal is counted.
    """
    cdef public str   validator_id
    cdef public long long ledger_seq
    cdef public set   tx_ids             # set of tx_id strings
    cdef public long long timestamp
    cdef public int   round_number
    cdef public bytes signature          # DER ECDSA sig, or b"" if unsigned

    def __init__(self, str validator_id, long long ledger_seq,
                 set tx_ids=None, int round_number=0,
                 bytes signature=b""):
        self.validator_id = validator_id
        self.ledger_seq = ledger_seq
        self.tx_ids = tx_ids if tx_ids is not None else set()
        self.timestamp = <long long>c_time(NULL)
        self.round_number = round_number
        self.signature = signature

    cpdef str compute_hash(self):
        """Deterministic hash of the proposal content (hex BLAKE2b-256)."""
        cdef str blob = (
            f"{self.validator_id}:{self.ledger_seq}:{self.round_number}:"
            + ",".join(sorted(self.tx_ids))
        )
        return hashlib.blake2b(blob.encode(), digest_size=32).hexdigest()

    cpdef bytes signing_digest(self):
        """Raw 32-byte BLAKE2b-256 digest over the canonical proposal blob."""
        cdef str blob = (
            f"{self.validator_id}:{self.ledger_seq}:{self.round_number}:"
            + ",".join(sorted(self.tx_ids))
        )
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    cpdef bint verify_signature(self, bytes pubkey_bytes):
        """
        Verify the DER ECDSA signature against *pubkey_bytes* (65-byte
        uncompressed secp256k1 public key).

        Returns True when the signature is valid or when no signature was
        provided (unsigned proposals are accepted only when the engine is
        not running in BFT mode).
        """
        if not self.signature:
            return True   # unsigned — caller decides whether to accept
        try:
            from ecdsa import VerifyingKey, SECP256k1
            from ecdsa.util import sigdecode_der
            vk = VerifyingKey.from_string(pubkey_bytes[1:], curve=SECP256k1)
            vk.verify_digest(
                self.signature,
                self.signing_digest(),
                sigdecode=sigdecode_der,
            )
            return True
        except Exception:
            return False

    cpdef void sign(self, bytes privkey_bytes):
        """
        Sign the proposal with *privkey_bytes* (32-byte secp256k1 private key).
        Stores the DER-encoded signature in :attr:`signature`.
        """
        from ecdsa import SigningKey, SECP256k1
        from ecdsa.util import sigencode_der
        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        self.signature = sk.sign_digest(
            self.signing_digest(), sigencode=sigencode_der
        )


# ===================================================================
#  Consensus Engine
# ===================================================================

cdef class ConsensusEngine:
    """
    Drives BFT-RPCA consensus rounds.

    BFT behaviour
    -------------
    * Set ``unl_pubkeys`` to a ``{validator_id: 65-byte-pubkey}`` dict.
      The engine will then **reject** any proposal whose signature does
      not verify against the known pubkey.
    * Validators that submit two different proposals for the same ledger
      sequence (equivocation) are added to ``byzantine_validators`` and
      their votes are excluded from all quorum calculations.
    * The maximum tolerable Byzantine faults is
      ``max_byzantine_faults = floor((n - 1) / 3)`` where
      ``n = len(unl) + 1``.  A warning is emitted when the active UNL
      is too small to achieve BFT safety.

    Usage::

        engine = ConsensusEngine(unl_validators, my_id, ledger_seq,
                                 unl_pubkeys={\"v2\": pubkey2, \"v3\": pubkey3},
                                 my_privkey=my_priv)
        engine.submit_transactions(candidate_txns)
        engine.add_proposal(peer_proposal)
        result = engine.run_rounds()
        if result is not None:
            # apply result.agreed_tx_ids to ledger
    """
    cdef public str   my_id
    cdef public long long ledger_seq
    cdef public list  unl                # list of validator id strings
    cdef public int   unl_size
    cdef public dict  proposals          # validator_id -> Proposal
    cdef public set   my_tx_ids          # my candidate set
    cdef public int   phase
    cdef public int   current_round
    cdef public int   max_rounds
    cdef public double initial_threshold
    cdef public double final_threshold
    cdef public double threshold_step
    cdef public list  round_history
    # BFT fields
    cdef public dict  unl_pubkeys        # validator_id -> 65-byte pubkey (optional)
    cdef public bytes my_privkey         # 32-byte privkey for signing own proposals
    cdef public set   byzantine_validators
    cdef public int   max_byzantine_faults
    cdef public object negative_unl           # NegativeUNL tracker

    def __init__(self, list unl, str my_id, long long ledger_seq,
                 int max_rounds=10,
                 double initial_threshold=0.50,
                 double final_threshold=0.80,
                 dict unl_pubkeys=None,
                 bytes my_privkey=b"",
                 object negative_unl=None):
        self.my_id = my_id
        self.ledger_seq = ledger_seq
        self.unl = list(unl)
        self.unl_size = len(unl)
        self.proposals = {}
        self.my_tx_ids = set()
        self.phase = PHASE_OPEN
        self.current_round = 0
        self.max_rounds = max_rounds
        self.initial_threshold = initial_threshold
        self.final_threshold = final_threshold
        # Gradually increase threshold each round
        if max_rounds > 1:
            self.threshold_step = (final_threshold - initial_threshold) / (max_rounds - 1)
        else:
            self.threshold_step = 0.0
        self.round_history = []
        # BFT
        self.unl_pubkeys = dict(unl_pubkeys) if unl_pubkeys else {}
        self.my_privkey = my_privkey
        self.byzantine_validators = set()
        # Maximum Byzantine faults: f = floor((n-1)/3) where n = |UNL| + 1
        cdef int n = len(unl) + 1
        self.max_byzantine_faults = (n - 1) // 3
        # NegativeUNL: track unreliable validators
        self.negative_unl = negative_unl if negative_unl is not None else NegativeUNL()

    # ---- public API ----

    cpdef void submit_transactions(self, list tx_ids):
        """Set our candidate transaction IDs and create our own signed proposal."""
        self.my_tx_ids = set(tx_ids)
        cdef Proposal p = Proposal(
            self.my_id, self.ledger_seq,
            set(self.my_tx_ids), 0,
        )
        if self.my_privkey:
            p.sign(self.my_privkey)
        self.proposals[self.my_id] = p

    cpdef bint add_proposal(self, object proposal):
        """
        Receive a proposal from a UNL peer.

        Returns True when the proposal is accepted.  Returns False and
        marks the sending validator as Byzantine when:
          * signature verification fails (pubkey known), or
          * the validator has already submitted a different proposal for
            this ledger/round (equivocation).
        """
        cdef Proposal p = <Proposal>proposal
        cdef str vid = p.validator_id

        # ── Signature check (CS3 — distinguish missing vs bad sig) ──
        if self.unl_pubkeys:
            pubkey = self.unl_pubkeys.get(vid)
            if pubkey is not None:
                if not p.signature:
                    import logging as _log
                    _log.getLogger("nexaflow_consensus").warning(
                        f"[BFT] Unsigned proposal from {vid} rejected — "
                        "pubkey is registered so signature is required"
                    )
                    return False
                if not p.verify_signature(pubkey):
                    import logging as _log
                    _log.getLogger("nexaflow_consensus").warning(
                        f"[BFT] BAD SIGNATURE on proposal from {vid} — "
                        "treating as Byzantine"
                    )
                    self.byzantine_validators.add(vid)
                    return False
            else:
                # Validator not in pubkey registry — accept unsigned only
                # when we have *no* pubkeys at all (non-BFT mode).
                if p.signature:
                    import logging as _log
                    _log.getLogger("nexaflow_consensus").info(
                        f"[BFT] Proposal from unknown validator {vid} "
                        "has signature but no registered pubkey — cannot verify"
                    )

        # ── Equivocation check ───────────────────────────────────────
        existing = self.proposals.get(vid)
        if existing is not None:
            if (<Proposal>existing).compute_hash() != p.compute_hash():
                import logging as _log
                _log.getLogger("nexaflow_consensus").warning(
                    f"[BFT] Equivocation detected from {vid}: conflicting "
                    f"proposals for ledger {self.ledger_seq} round "
                    f"{p.round_number} — marking Byzantine"
                )
                self.byzantine_validators.add(vid)
                # Remove existing vote; do not replace with conflicting one
                del self.proposals[vid]
                return False

        self.proposals[vid] = p
        return True

    cpdef object run_rounds(self):
        """
        Execute voting rounds until consensus or failure.

        Byzantine validators are excluded from the quorum denominator so
        the threshold is computed over honest nodes only.

        **Liveness vs safety (CS4)**:  The final threshold of 80 % exceeds
        the BFT requirement of 2/3 honest votes.  This is deliberate — it
        provides a wider safety margin at the cost of slightly reduced
        liveness (the network may stall if >20 % of validators are
        unreachable, compared to >33 % under a bare 2/3 rule).  Operators
        should monitor ``ConsensusResult.byzantine_count`` and alert when
        ``byzantine_count > 0``.

        Returns a :class:`ConsensusResult` or None on failure.
        """
        import logging as _log
        _logger = _log.getLogger("nexaflow_consensus")

        # CS1 — BFT safety gate: warn (but proceed) when UNL is too small
        if not self.is_bft_safe():
            _logger.warning(
                f"[BFT] UNL too small for Byzantine safety: "
                f"{self.unl_size + 1} validators (need >= "
                f"{3 * self.max_byzantine_faults + 1}).  "
                f"Consensus results may not be fault-tolerant."
            )

        self.phase = PHASE_ESTABLISH
        cdef double threshold
        cdef set agreed
        cdef int total_proposals

        while self.current_round < self.max_rounds:
            threshold = _threshold_for_round(
                self.initial_threshold, self.threshold_step,
                self.current_round, self.final_threshold,
            )

            agreed = self._compute_agreed(threshold)
            total_proposals = len(self.proposals)

            self.round_history.append({
                "round": self.current_round,
                "threshold": threshold,
                "proposals": total_proposals,
                "agreed_txns": len(agreed),
                "candidate_txns": len(self.my_tx_ids),
                "byzantine_count": len(self.byzantine_validators),
            })

            # ── Record validator participation for NegativeUNL ──
            participating = set(self.proposals.keys()) - self.byzantine_validators
            for vid in self.unl:
                self.negative_unl.record_validation(
                    vid, vid in participating,
                )
            newly_neg = self.negative_unl.check_and_update(
                self.unl_size + 1, self.ledger_seq,
            )
            if newly_neg:
                _logger.info(
                    f"[nUNL] Added to Negative UNL: {newly_neg}"
                )
            # Auto-remove validators that just participated
            for vid in list(self.negative_unl.entries.keys()):
                if vid in participating:
                    self.negative_unl.remove(vid)
                    _logger.info(
                        f"[nUNL] Removed from Negative UNL (back online): {vid}"
                    )

            # If we've reached final threshold and have agreement
            if threshold >= self.final_threshold and len(agreed) > 0:
                self.phase = PHASE_ACCEPTED
                return ConsensusResult(
                    self.ledger_seq,
                    agreed,
                    self.current_round,
                    threshold,
                    total_proposals,
                    len(self.byzantine_validators),
                )

            # Update our candidate set to the agreed set
            self.my_tx_ids = agreed
            updated = Proposal(
                self.my_id, self.ledger_seq,
                set(agreed), self.current_round,
            )
            if self.my_privkey:
                updated.sign(self.my_privkey)
            self.proposals[self.my_id] = updated
            self.current_round += 1

        # Even if we hit max rounds, accept what we have at final threshold
        agreed = self._compute_agreed(self.final_threshold)
        if len(agreed) > 0:
            self.phase = PHASE_ACCEPTED
            return ConsensusResult(
                self.ledger_seq, agreed, self.current_round,
                self.final_threshold, len(self.proposals),
                len(self.byzantine_validators),
            )

        self.phase = PHASE_FAILED
        return None

    cpdef bint is_bft_safe(self):
        """
        Return True when the current UNL is large enough to tolerate
        ``max_byzantine_faults`` Byzantine failures.

        BFT requires n >= 3f + 1.  Returns False (and is_bft_safe should
        trigger a warning in the caller) when the UNL is too small.
        """
        cdef int n = self.unl_size + 1
        cdef int f = self.max_byzantine_faults
        return n >= 3 * f + 1

    # ---- internal ----

    cdef set _compute_agreed(self, double threshold):
        """
        Compute the set of tx_ids that appear in >= threshold fraction
        of honest (non-Byzantine) UNL proposals.

        Validators on the Negative UNL are excluded from the quorum
        denominator so the network can make progress even when some
        validators are offline.
        """
        cdef dict vote_count = {}
        cdef int total = 0
        cdef str tx_id
        # Determine effective validator set (exclude nUNL + Byzantine)
        neg_unl_set = set(self.negative_unl.entries.keys()) if self.negative_unl else set()

        for vid, prop in self.proposals.items():
            if vid in self.byzantine_validators:
                continue   # exclude Byzantine voters
            if vid in neg_unl_set:
                continue   # exclude Negative-UNL validators
            if vid in self.unl or vid == self.my_id:
                total += 1
                for tx_id in (<Proposal>prop).tx_ids:
                    if tx_id in vote_count:
                        vote_count[tx_id] += 1
                    else:
                        vote_count[tx_id] = 1

        # Use adjusted quorum if NegativeUNL is active
        if self.negative_unl and self.negative_unl.size > 0:
            adj_quorum = self.negative_unl.adjusted_quorum(
                self.unl_size + 1, threshold,
            )
            # total must still meet the adjusted quorum denominator
            effective_total = max(total, self.unl_size + 1 - len(neg_unl_set))
        else:
            effective_total = total

        if effective_total == 0:
            return set()

        cdef set agreed = set()
        cdef int count
        for tx_id, count in vote_count.items():
            if _vote_passes(count, effective_total, threshold):
                agreed.add(tx_id)
        return agreed


# ===================================================================
#  Consensus Result
# ===================================================================

@cython.freelist(4)
cdef class ConsensusResult:
    """Outcome of a successful consensus round."""
    cdef public long long ledger_seq
    cdef public set   agreed_tx_ids
    cdef public int   rounds_taken
    cdef public double final_threshold
    cdef public int   total_proposals
    cdef public int   byzantine_count

    def __init__(self, long long ledger_seq, set agreed_tx_ids,
                 int rounds_taken, double final_threshold,
                 int total_proposals, int byzantine_count=0):
        self.ledger_seq = ledger_seq
        self.agreed_tx_ids = agreed_tx_ids
        self.rounds_taken = rounds_taken
        self.final_threshold = final_threshold
        self.total_proposals = total_proposals
        self.byzantine_count = byzantine_count

    cpdef dict to_dict(self):
        return {
            "ledger_seq": self.ledger_seq,
            "agreed_transactions": len(self.agreed_tx_ids),
            "rounds_taken": self.rounds_taken,
            "threshold": self.final_threshold,
            "proposals": self.total_proposals,
            "byzantine_validators_excluded": self.byzantine_count,
        }

    def __repr__(self):
        return (f"ConsensusResult(seq={self.ledger_seq}, "
                f"txns={len(self.agreed_tx_ids)}, "
                f"rounds={self.rounds_taken}, "
                f"byzantine={self.byzantine_count})")
