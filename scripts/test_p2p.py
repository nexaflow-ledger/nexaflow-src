#!/usr/bin/env python3
"""Integration test: two nodes connect, exchange transactions, and run consensus."""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_node import NexaFlowNode


async def test_two_nodes():
    print("=" * 60)
    print("  NexaFlow P2P Integration Test")
    print("=" * 60)

    # Start node 1
    n1 = NexaFlowNode("validator-1", port=19001)
    await n1.start()
    n1.fund_local(n1.wallet.address, 50000.0)
    print(f"\n[1] Node 1 started: {n1.wallet.address}")

    # Start node 2
    n2 = NexaFlowNode("validator-2", port=19002, peers=["127.0.0.1:19001"])
    await n2.start()
    n2.fund_local(n2.wallet.address, 50000.0)
    print(f"[2] Node 2 started: {n2.wallet.address}")

    # Wait for peer connection
    await asyncio.sleep(2)
    print(f"\n[3] Peers — N1: {n1.p2p.peer_count}, N2: {n2.p2p.peer_count}")
    assert n1.p2p.peer_count >= 1, "Node 1 has no peers!"
    assert n2.p2p.peer_count >= 1, "Node 2 has no peers!"
    print("    ✓ Peers connected")

    # Send a payment from node1's wallet to node2's wallet
    print(f"\n[4] Balances before payment:")
    print(f"    N1: {n1.ledger.get_balance(n1.wallet.address):.6f} NXF")
    print(f"    N2: {n2.ledger.get_balance(n2.wallet.address):.6f} NXF")

    tx = await n1.send_payment(n2.wallet.address, 100.0, "NXF", "test payment")
    print(f"\n[5] TX submitted: {tx.tx_id[:24]}...")

    # Wait for broadcast propagation
    await asyncio.sleep(1)
    print(f"    N1 pool: {len(n1.tx_pool)} txns, N2 pool: {len(n2.tx_pool)} txns")

    # Run consensus on node 1
    print(f"\n[6] Running consensus round...")
    await n1.run_consensus()

    print(f"\n[7] Balances AFTER consensus:")
    print(f"    N1: {n1.ledger.get_balance(n1.wallet.address):.6f} NXF")
    n2_bal = n1.ledger.get_balance(n2.wallet.address)
    print(f"    N2 (on N1's ledger): {n2_bal:.6f} NXF")

    assert n2_bal > 0, "Payment was not applied!"
    print("    ✓ Payment applied successfully")

    # Check ledger state
    print(f"\n[8] Ledger state:")
    summary = n1.ledger.get_state_summary()
    for k, v in summary.items():
        print(f"    {k}: {v}")

    if n1.ledger.closed_ledgers:
        last = n1.ledger.closed_ledgers[-1]
        print(f"    last_hash: {last.hash[:32]}...")

    # Cleanup
    await n1.stop()
    await n2.stop()

    print(f"\n{'=' * 60}")
    print("  ALL TESTS PASSED ✓")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(test_two_nodes())
