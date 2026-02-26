# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
"""
Cython-optimized NexaFlow Protocol Consensus Algorithm (RPCA) for NexaFlow.

Simplified model of NexaFlow's consensus:
  1. Each validator proposes a candidate transaction set.
  2. Proposals are exchanged across the Unique Node List (UNL).
  3. Voting rounds increase the threshold until ≥80 % agreement.
  4. Agreed transactions are applied; ledger is closed.

This module also implements a fast proposal-voting engine with
configurable thresholds and round limits.
"""

import hashlib

cimport cython
from libc.time cimport time as c_time


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
    """A validator's proposed transaction set for a ledger round."""
    cdef public str validator_id
    cdef public long long ledger_seq
    cdef public set tx_ids             # set of tx_id strings
    cdef public long long timestamp
    cdef public int round_number

    def __init__(self, str validator_id, long long ledger_seq,
                 set tx_ids=None, int round_number=0):
        self.validator_id = validator_id
        self.ledger_seq = ledger_seq
        self.tx_ids = tx_ids if tx_ids is not None else set()
        self.timestamp = <long long>c_time(NULL)
        self.round_number = round_number

    cpdef str compute_hash(self):
        """Deterministic hash of the proposal for comparison."""
        cdef str blob = f"{self.validator_id}:{self.ledger_seq}:" + \
                        ",".join(sorted(self.tx_ids))
        return hashlib.sha256(blob.encode()).hexdigest()


# ===================================================================
#  Consensus Engine
# ===================================================================

cdef class ConsensusEngine:
    """
    Drives the RPCA consensus rounds.

    Usage:
        engine = ConsensusEngine(unl_validators, my_id, ledger_seq)
        engine.submit_transactions(candidate_txns)
        engine.add_proposal(peer_proposal)
        ...
        result = engine.run_rounds()
        if result is not None:
            # apply result.agreed_tx_ids to ledger
    """
    cdef public str my_id
    cdef public long long ledger_seq
    cdef public list unl                # list of validator id strings
    cdef public int unl_size
    cdef public dict proposals         # validator_id -> Proposal
    cdef public set my_tx_ids          # my candidate set
    cdef public int phase
    cdef public int current_round
    cdef public int max_rounds
    cdef public double initial_threshold
    cdef public double final_threshold
    cdef public double threshold_step
    cdef public list round_history

    def __init__(self, list unl, str my_id, long long ledger_seq,
                 int max_rounds=10,
                 double initial_threshold=0.50,
                 double final_threshold=0.80):
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

    # ---- public API ----

    cpdef void submit_transactions(self, list tx_ids):
        """Set our candidate transaction IDs."""
        self.my_tx_ids = set(tx_ids)
        # Create our own proposal
        cdef Proposal p = Proposal(self.my_id, self.ledger_seq,
                                    set(self.my_tx_ids), 0)
        self.proposals[self.my_id] = p

    cpdef void add_proposal(self, object proposal):
        """Receive a proposal from a UNL peer."""
        self.proposals[(<Proposal>proposal).validator_id] = proposal

    cpdef object run_rounds(self):
        """
        Execute voting rounds until consensus or failure.
        Returns a ConsensusResult or None on failure.
        """
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
            })

            # If we've reached final threshold and have agreement
            if threshold >= self.final_threshold and len(agreed) > 0:
                self.phase = PHASE_ACCEPTED
                return ConsensusResult(
                    self.ledger_seq,
                    agreed,
                    self.current_round,
                    threshold,
                    total_proposals,
                )

            # Update our candidate set to the agreed set
            self.my_tx_ids = agreed
            self.proposals[self.my_id] = Proposal(
                self.my_id, self.ledger_seq, set(agreed), self.current_round
            )
            self.current_round += 1

        # Even if we hit max rounds, accept what we have at final threshold
        agreed = self._compute_agreed(self.final_threshold)
        if len(agreed) > 0:
            self.phase = PHASE_ACCEPTED
            return ConsensusResult(
                self.ledger_seq, agreed, self.current_round,
                self.final_threshold, len(self.proposals),
            )

        self.phase = PHASE_FAILED
        return None

    # ---- internal ----

    cdef set _compute_agreed(self, double threshold):
        """
        Compute the set of tx_ids that appear in >= threshold fraction
        of UNL proposals.
        """
        cdef dict vote_count = {}
        cdef int total = 0
        cdef str tx_id

        for vid, prop in self.proposals.items():
            if vid in self.unl or vid == self.my_id:
                total += 1
                for tx_id in (<Proposal>prop).tx_ids:
                    if tx_id in vote_count:
                        vote_count[tx_id] += 1
                    else:
                        vote_count[tx_id] = 1

        if total == 0:
            return set()

        cdef set agreed = set()
        cdef int count
        for tx_id, count in vote_count.items():
            if _vote_passes(count, total, threshold):
                agreed.add(tx_id)
        return agreed


# ===================================================================
#  Consensus Result
# ===================================================================

@cython.freelist(4)
cdef class ConsensusResult:
    """Outcome of a successful consensus round."""
    cdef public long long ledger_seq
    cdef public set agreed_tx_ids
    cdef public int rounds_taken
    cdef public double final_threshold
    cdef public int total_proposals

    def __init__(self, long long ledger_seq, set agreed_tx_ids,
                 int rounds_taken, double final_threshold,
                 int total_proposals):
        self.ledger_seq = ledger_seq
        self.agreed_tx_ids = agreed_tx_ids
        self.rounds_taken = rounds_taken
        self.final_threshold = final_threshold
        self.total_proposals = total_proposals

    cpdef dict to_dict(self):
        return {
            "ledger_seq": self.ledger_seq,
            "agreed_transactions": len(self.agreed_tx_ids),
            "rounds_taken": self.rounds_taken,
            "threshold": self.final_threshold,
            "proposals": self.total_proposals,
        }

    def __repr__(self):
        return (f"ConsensusResult(seq={self.ledger_seq}, "
                f"txns={len(self.agreed_tx_ids)}, "
                f"rounds={self.rounds_taken})")
