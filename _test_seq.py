"""Quick smoke test for multi-TX sequence fix."""
from nexaflow_gui.backend import NodeBackend

b = NodeBackend()

w1 = b.create_wallet("TestWallet")
addr1 = w1["address"]

genesis_addr = b._primary_node.ledger.genesis_account
b.network.fund_account(addr1, 10_000_000)
print(f"Funded {addr1[:16]}... balance: {b.get_balance(addr1):,.2f}")

w2 = b.create_wallet("TestWallet2")
addr2 = w2["address"]
print(f"Created {addr2[:16]}...")

for i in range(1, 4):
    acc = b._primary_node.ledger.get_account(addr1)
    print(f"  Before TX {i}: account seq={acc.sequence}")
    result = b.send_payment(addr1, addr2, 1000.0)
    accepted = result.get("_accepted", False) if result else False
    acc = b._primary_node.ledger.get_account(addr1)
    print(f"  After  TX {i}: accepted={accepted}, account seq={acc.sequence}")

print(f"Final balances: sender={b.get_balance(addr1):,.2f}, receiver={b.get_balance(addr2):,.2f}")
