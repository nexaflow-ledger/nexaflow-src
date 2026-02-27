# NexaFlow

> A production-ready cryptocurrency node and protocol library built in Python,
> with Cython-compiled core modules for high-performance cryptography, consensus,
> and confidential transactions.

---

## Features

| Area | Description |
|------|-------------|
| **Cython-optimised core** | Crypto, transactions, ledger, consensus & privacy primitives compiled to C |
| **ECDSA / secp256k1** | Key-pair generation, deterministic wallet derivation, transaction signing |
| **Confidential transactions** | Pedersen commitments, LSAG ring signatures, stealth addresses, range proofs |
| **Double-spend prevention** | Per-transaction key images tracked on-ledger; tx-id replay detection |
| **Trust lines & IOUs** | Credit relationships between accounts with configurable limits and transfer rates |
| **Payment path finding** | Multi-hop DFS through the trust graph for cross-currency settlement |
| **RPCA consensus** | NexaFlow Protocol Consensus Algorithm with threshold escalation |
| **Native token (NXF)** | 100 billion initial supply; deflationary fee burning; interest minting from staking |
| **TCP P2P networking** | Async JSON-over-TCP peer discovery, broadcast & keepalive |
| **REST API** | `aiohttp`-based HTTP API for wallets, transactions & node status |
| **Order book / DEX** | In-memory limit-order matching engine for cross-currency trades |
| **Staking with interest** | Tiered lock-up staking (Flexible–365 days) with dynamic APY and early-cancel penalties |
| **Wallet encryption** | PBKDF2-HMAC-SHA256 + BLAKE2b-CTR encrypted wallet export |
| **SQLite persistence** | Optional durable storage for ledger state |
| **TOML configuration** | Flexible file-based node configuration |
| **Structured logging** | JSON or human-readable logs with configurable verbosity |
| **Docker support** | Multi-node deployment via `docker-compose` |

---

## Privacy & Confidential Transactions

NexaFlow supports **fully confidential payments** that hide amounts, sender identity, and recipient identity while remaining cryptographically verifiable on-chain.

| Primitive | Description |
|-----------|-------------|
| **Pedersen Commitments** | Homomorphic commitments that hide the payment amount: $C = v \cdot G + b \cdot H$ |
| **Range Proofs** | Zero-knowledge proof that the committed value is non-negative, without revealing it |
| **Stealth Addresses** | One-time recipient addresses derived from a view/spend key pair — only the recipient can identify their outputs |
| **View Tags** | 1-byte scan hint that lets a recipient skip non-matching outputs with minimal computation |
| **LSAG Ring Signatures** | Linkable spontaneous anonymous group signatures — proves membership in a ring of public keys without revealing which member signed |
| **Key Images** | Deterministic per-spend tag that enables double-spend detection without revealing the spender |

### Confidential Payment Flow

```
Sender                                  Recipient
──────                                  ─────────
1. Derive one-time stealth address  ──►  Scans ledger outputs against view key
   from recipient's (view_pub, spend_pub)    + view tag fast-path filter
2. Commit amount:  C = v·G + b·H    ──►  Discovers output; recovers one-time spend key
3. Prove C ≥ 0 (range proof)
4. Sign with LSAG over ring of decoy pubkeys
5. Publish (C, stealth_addr, range_proof, ring_sig, key_image)
```

### Python API

```python
from nexaflow_core.wallet import Wallet
from nexaflow_core.ledger import Ledger

sender    = Wallet.create()
recipient = Wallet.create()

ledger = Ledger(total_supply=100_000_000_000.0, genesis_account="rGenesis")
ledger.create_account(sender.address, 1_000.0)

# Build and submit a confidential payment
tx = sender.sign_confidential_payment(
    recipient.view_public_key,
    recipient.spend_public_key,
    amount=50.0,
    fee=0.001,
)
ledger.apply_payment(tx)

# Recipient scans for their outputs — nothing else is visible on-chain
found = recipient.scan_confidential_outputs(ledger)
# found[0] contains stealth_addr, commitment, ephemeral_pub, one_time_priv, …
```

---

## Staking

NexaFlow supports **tiered staking** with dynamic interest rates and early-cancellation penalties.

### Tiers

| Tier | Lock Period | Base APY | Description |
|------|------------|----------|-------------|
| Flexible | None | 2 % | Withdraw any time, no penalty |
| 30 Days | 30 days | 5 % | |
| 90 Days | 90 days | 8 % | |
| 180 Days | 180 days | 12 % | |
| 365 Days | 365 days | 15 % | Highest yield |

### Dynamic Interest

Base APY is scaled by a **demand multiplier** (0.5×–2×) derived from the network staking ratio:

$$\text{effective\_apy} = \text{base\_apy} \times \text{demand\_multiplier}$$

When fewer tokens are staked the multiplier rises to attract capital.  When too many are staked it drops to release liquidity.  Target ratio = 30 %.

### Early Cancellation

Locked-tier stakes can be cancelled before maturity at a penalty:

- **Interest penalty** — forfeit 50–90 % of accrued interest (scaled by tier APY)
- **Principal penalty** — burn 2–10 % of principal (scaled by tier APY)
- **Time decay** — penalties decrease linearly as the stake approaches maturity

Flexible-tier stakes have zero penalty.

---

## Tokenomics

NexaFlow uses a **deflationary fee-burning** model with **interest-based minting** as the only source of new coins after genesis.

### Supply Rules

| Rule | Detail |
|------|--------|
| **Initial supply** | 100 billion NXF minted to the genesis account at network launch |
| **Fee burning** | Every transaction fee is permanently destroyed — removed from `total_supply` |
| **Interest minting** | When a staked position matures, the earned interest is newly minted — added to `total_supply` |
| **Early-cancel burn** | Principal penalties from early stake cancellation are also permanently burned |
| **No other minting** | Coins can **only** enter circulation from the genesis allocation or staking interest — there is no block reward, no inflation schedule, and no admin mint |

### Economic Dynamics

- **Deflationary pressure** — every transaction shrinks the supply
- **Inflationary pressure** — staking interest grows the supply
- **Equilibrium** — the dynamic APY multiplier adjusts interest rates based on the staking ratio, creating a self-balancing feedback loop between burning and minting
- **Net effect** — under normal activity the burn rate exceeds interest minting, making NXF structurally deflationary over time

### API Examples

```bash
# Stake 1000 NXF for 90 days (tier 2)
curl -X POST http://localhost:8080/tx/stake \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"amount": 1000.0, "tier": 2}'

# Check staking info
curl http://localhost:8080/staking/rMyAddress

# Cancel a stake early
curl -X POST http://localhost:8080/tx/unstake \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"stake_id": "TX_ID_HERE"}'
```

---

## Quick Start

### Prerequisites

- Python ≥ 3.9
- A C compiler — Xcode Command Line Tools on macOS, `build-essential` on Debian/Ubuntu

### Install

```bash
git clone https://github.com/nexaflow/nexaflow.git
cd nexaflow

python -m venv .venv && source .venv/bin/activate

pip install -e ".[dev]"

# Compile Cython extensions
python setup.py build_ext --inplace
```

### Run a Single Node

```bash
python run_node.py --node-id alice --port 9001
```

### Run a Two-Node Test Network

```bash
./scripts/start_both.sh
```

Or manually in separate terminals:

```bash
./scripts/start_node1.sh   # Terminal 1
./scripts/start_node2.sh   # Terminal 2
```

### Run via the Installed CLI

```bash
nexaflow-node --node-id alice --port 9001
```

---

## REST API

Start a node with the built-in HTTP API:

```bash
python run_node.py --node-id alice --port 9001 --api-port 8080
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Node & ledger status |
| GET | `/balance/{address}` | Account balance |
| POST | `/tx/payment` | Submit a standard payment |
| POST | `/tx/trust` | Set a trust line |
| GET | `/peers` | Connected peers |
| GET | `/ledger` | Latest closed ledger info |
| POST | `/consensus` | Trigger a consensus round |
| GET | `/orderbook/{base}/{counter}` | Order book snapshot |
| POST | `/tx/stake` | Submit a stake |
| POST | `/tx/unstake` | Cancel a stake (early cancellation) |
| GET | `/staking/{address}` | Staking summary for an address |
| GET | `/staking` | Global staking pool stats & tier info |
| GET | `/health` | Deep health check |

---

## Configuration

```bash
cp nexaflow.example.toml nexaflow.toml
# Edit nexaflow.toml as needed
```

See [`nexaflow.example.toml`](nexaflow.example.toml) for all available options.

---

## Project Layout

```
nexaflow-src/
├── nexaflow_core/
│   ├── crypto_utils.pyx    # Hashing, Base58, ECDSA key ops (Cython)
│   ├── transaction.pyx     # Transaction types, serialisation & privacy fields (Cython)
│   ├── ledger.pyx          # Ledger state machine, UTXO tracking, fee logic (Cython)
│   ├── consensus.pyx       # RPCA consensus engine (Cython)
│   ├── privacy.pyx         # Pedersen, RingSignature, StealthAddress, RangeProof (Cython)
│   ├── wallet.py           # HD wallet, signing, confidential payment helpers
│   ├── account.py          # High-level account abstraction
│   ├── trust_line.py       # Trust-line graph
│   ├── payment_path.py     # Multi-hop path finding (DFS)
│   ├── validator.py        # Transaction validation pipeline
│   ├── network.py          # In-memory network simulation
│   ├── p2p.py              # TCP P2P layer
│   ├── api.py              # aiohttp REST API server
│   ├── storage.py          # SQLite persistence
│   ├── order_book.py       # DEX limit-order engine
│   ├── staking.py          # Tiered staking pool with dynamic APY
│   ├── config.py           # TOML configuration loader
│   └── logging_config.py   # Structured logging
├── nexaflow_gui/           # Optional desktop GUI
├── tests/                  # Test suite (670+ tests)
├── scripts/                # Node launch helpers
├── run_node.py             # CLI node runner
├── run_tests.py            # Python test runner (builds + runs all tests)
├── setup.py                # Cython build config
├── pyproject.toml          # PEP 517/518 metadata
├── Makefile                # Dev workflow shortcuts
├── Dockerfile              # Container image
└── docker-compose.yml      # Multi-node deployment
```

---

## Testing

```bash
# Full test suite (build + run)
python run_tests.py

# Skip Cython rebuild
python run_tests.py --no-build

# Filter by keyword
python run_tests.py -k staking

# Via make
make test

# With line coverage
make coverage

# Single module
pytest tests/test_privacy.py -v
```

The `run_tests.py` script automatically detects and skips test modules with missing optional dependencies (e.g. `aiohttp`).

---

## Docker

```bash
# Build and launch a two-node network
make docker-up

# Tear down
make docker-down
```

---

## Development

```bash
pip install -e ".[dev]"

make lint        # ruff
make typecheck   # mypy
make format      # ruff format + fix
make build       # rebuild Cython extensions
```

---

## Architecture

### Consensus

NexaFlow uses the **NexaFlow Protocol Consensus Algorithm (RPCA)**:

1. Each validator proposes its candidate transaction set.
2. Proposals are exchanged over the P2P network.
3. Transactions reaching ≥ 50 % support enter the next round.
4. The support threshold escalates by 5 % each round up to 80 %.
5. Transactions exceeding the final threshold are applied to the ledger.
6. The ledger is closed with a chained BLAKE2b-256 hash.

### Ledger Model

- Account-based model for standard payments and trust lines
- UTXO-style confidential outputs for private payments
- Native NXF + arbitrary IOU currencies via trust lines
- Account reserves prevent ledger spam
- Deterministic hash-chaining across closed ledgers
- Separate key-image set and applied-tx-id set for double-spend prevention

### Cryptographic Primitives

All performance-critical cryptography is implemented in Cython (`privacy.pyx`) and compiled to native C:

- **BLAKE2b-256** — used for all hashing (transaction IDs, ledger headers, proposal digests, checksums)
- **secp256k1 ECDSA** via the `ecdsa` library
- **Pedersen Commitments** over secp256k1: $C = v \cdot G + b \cdot H$
- **LSAG Ring Signatures** — linkable, spontaneous, provably secure under the discrete logarithm assumption
- **Stealth Addresses** — Diffie-Hellman shared secret over ephemeral keypairs
- **Range Proofs** — deterministic hash-based proofs keyed on the Pedersen blinding factor

---

## Security

- All cryptographic operations use the secp256k1 curve (same as Bitcoin)
- Wallet private keys are encrypted at rest with PBKDF2-HMAC-SHA256 + BLAKE2b-CTR
- Confidential transaction amounts are never written in plaintext — only Pedersen commitments appear on-chain
- Ring signatures provide sender anonymity within a configurable anonymity set
- Stealth addresses ensure no two outputs are linkable to the same recipient without the recipient's view key
- Input validation and error handling on all public API surfaces

> **Note:** While NexaFlow's cryptographic design is sound, the codebase has not yet undergone a formal third-party security audit. Use appropriate caution when deploying with real funds until an audit is completed.

---

## License

[MIT](LICENSE) — see the `LICENSE` file for details.
