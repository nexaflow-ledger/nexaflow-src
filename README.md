# NexaFlow – A NexaFlow-like Cryptocurrency

> A fully-featured cryptocurrency built in Python with
> Cython-optimised core modules.

---

## Features

| Area | Description |
|------|-------------|
| **Cython-optimised core** | Crypto, transactions, ledger & consensus compiled to C for speed |
| **ECDSA signatures** | secp256k1 key-pairs, deterministic wallets, transaction signing |
| **Trust lines & IOUs** | NexaFlow-style credit relationships between accounts |
| **Payment path finding** | Multi-hop DFS through the trust graph |
| **RPCA consensus** | Simplified NexaFlow Protocol Consensus Algorithm with threshold escalation |
| **Native token (NXF)** | 100 billion pre-mined supply with configurable reserves |
| **TCP P2P networking** | Async JSON-over-TCP peer discovery, broadcast & keepalive |
| **REST API** | `aiohttp`-based HTTP API for wallets, transactions & node status |
| **Order book / DEX** | In-memory limit-order matching engine for cross-currency trades |
| **SQLite persistence** | Optional durable storage for ledger state |
| **TOML configuration** | Flexible file-based node configuration |
| **Structured logging** | JSON or human-readable logs with configurable verbosity |
| **Docker support** | Multi-node deployment via `docker-compose` |

---

## Quick Start

### Prerequisites

* Python ≥ 3.9
* A C compiler (for Cython extensions) — Xcode CLI tools on macOS, `build-essential` on Debian/Ubuntu

### Install

```bash
# Clone the repository
git clone https://github.com/nexaflow/nexaflow.git
cd nexaflow

# Create a virtual environment (recommended)
python -m venv .venv && source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Build Cython extensions in-place
python setup.py build_ext --inplace
```

### Run a Single Node

```bash
python run_node.py --node-id alice --port 9001
```

### Run a Two-Node Test Network

```bash
./start_both.sh
```

Or manually:

```bash
# Terminal 1
./start_node1.sh

# Terminal 2
./start_node2.sh
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
| POST | `/tx/payment` | Submit a payment |
| POST | `/tx/trust` | Set a trust line |
| GET | `/peers` | Connected peers |
| GET | `/ledger` | Latest closed ledger info |
| POST | `/consensus` | Trigger consensus round |
| GET | `/orderbook/{base}/{counter}` | Order book snapshot |

---

## Configuration

Copy the example and customise:

```bash
cp nexaflow.example.toml nexaflow.toml
```

See `nexaflow.example.toml` for all available options.

---

## Project Layout

```
nexaflow/
├── nexaflow_core/          # Core library
│   ├── crypto_utils.pyx  # Hashing, Base58, ECDSA (Cython)
│   ├── transaction.pyx   # Transaction types & serialisation (Cython)
│   ├── ledger.pyx        # Ledger state machine (Cython)
│   ├── consensus.pyx     # RPCA engine (Cython)
│   ├── wallet.py         # Wallet management & signing
│   ├── account.py        # High-level account abstraction
│   ├── trust_line.py     # Trust-line graph
│   ├── payment_path.py   # Path finding (DFS)
│   ├── validator.py      # Transaction validation pipeline
│   ├── network.py        # In-memory network simulation
│   ├── p2p.py            # Real TCP P2P layer
│   ├── api.py            # REST/HTTP API server
│   ├── storage.py        # SQLite ledger persistence
│   ├── order_book.py     # DEX matching engine
│   ├── config.py         # TOML configuration loader
│   └── logging_config.py # Structured logging setup
├── tests/                # Comprehensive test suite
├── benchmarks/           # Performance benchmarks
├── run_node.py           # Full CLI node runner
├── setup.py              # Build config (Cython fallback)
├── pyproject.toml        # PEP 517/518 metadata
├── Makefile              # Common dev commands
├── Dockerfile            # Container build
├── docker-compose.yml    # Multi-node deployment
└── .github/workflows/    # CI pipeline
```

---

## Testing

```bash
# Run all tests
make test

# With coverage
make coverage

# Or directly
pytest -v --tb=short
```

---

## Docker

```bash
# Build and run a two-node network
make docker-up

# Tear down
make docker-down
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Lint
make lint

# Type check
make typecheck

# Format
make format

# Build Cython extensions
make build
```

---

## Architecture

### Consensus

NexaFlow uses a simplified **NexaFlow Protocol Consensus Algorithm (RPCA)**:

1. Each validator proposes its candidate transaction set.
2. Proposals are exchanged over the P2P network.
3. Transactions reaching ≥ 50 % support enter the next round.
4. The threshold escalates by 5 % each round up to 80 %.
5. Transactions exceeding the final threshold are applied.
6. The ledger is closed with a chained SHA-256 hash.

### Ledger

* Account-based model (not UTXO)
* Native NXF + arbitrary IOU currencies via trust lines
* Account reserves prevent ledger spam
* Deterministic hash-chaining across closed ledgers

### Security Notes

This is an **educational project**.  It is **not audited** for production use.
Key simplifications include:

* Consensus trusts all connected peers (no Byzantine fault tolerance)
* No TLS on the P2P layer
* Simplified key derivation (SHA-256 of seed)

---

## License

[MIT](LICENSE) — see the `LICENSE` file for details.
