# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-01

### Added
- Core ECDSA cryptographic utilities (Cython-optimised)
- Transaction types: Payment, TrustSet, OfferCreate
- Ledger with account management, trust lines, and payment processing
- Simplified NexaFlow Protocol Consensus Algorithm (RPCA)
- Wallet management with deterministic key derivation
- High-level Account abstraction
- Trust-line graph with network-wide traversal
- Payment path finding (DFS through trust graph)
- Transaction validation pipeline
- In-memory network simulation with multi-validator consensus
- Real TCP-based P2P networking layer (JSON-over-TCP)
- Full interactive CLI for running validator nodes
- Bash scripts for launching multi-node test networks
- REST/HTTP API server with aiohttp
- Ledger persistence via SQLite storage backend
- Order book / DEX matching engine
- TOML-based configuration system
- Structured JSON logging
- PBKDF2+AES wallet encryption (replacing demo XOR cipher)
- MalformedPointError handling in signature verification
- Comprehensive test suite (239+ tests across all components)
- Docker and docker-compose for multi-node deployment
- GitHub Actions CI pipeline
- Makefile for common development tasks
- Benchmark suite for performance profiling
- Type checking (mypy) and linting (ruff) configuration

### Security
- Upgraded wallet encryption from XOR cipher to PBKDF2-HMAC-SHA256 + AES-256-CBC
- Fixed `verify()` to catch `MalformedPointError` for invalid public keys
