# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest `main` | ✅ |
| older tags | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in NexaFlow, **please do not open a
public GitHub issue.**

Instead, report it privately via one of the following:

- **Email:** [security@nexaflow.io](mailto:security@nexaflow.io)
- **GitHub Security Advisories:** Use the "Report a vulnerability" button on the
  [GitHub Security tab](../../security/advisories).

Please include:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce the issue (proof-of-concept code is appreciated).
3. Any relevant log output or stack traces.
4. The version of NexaFlow you are running.

## Response Timeline

| Action | SLA |
|--------|-----|
| Acknowledge receipt | 48 hours |
| Preliminary assessment | 5 business days |
| Patch release (critical) | 7 days |
| Patch release (high) | 14 days |
| Patch release (medium/low) | Next scheduled release |

## Disclosure Policy

We follow **coordinated disclosure**:

1. The reporter is credited (unless they prefer anonymity).
2. We prepare a fix and coordinate a release date with the reporter.
3. A CVE is requested where appropriate.
4. The advisory and fix are published simultaneously.

## Scope

The following are **in scope**:

- Cryptographic primitives (`crypto_utils.pyx`, `privacy.pyx`)
- Consensus logic (`consensus.pyx`)
- Transaction validation and ledger state machine (`transaction.pyx`, `ledger.pyx`)
- P2P networking (`p2p.py`) — message parsing, TLS configuration
- REST API (`api.py`) — authentication bypass, injection, denial of service
- Wallet key derivation and encryption (`wallet.py`)
- Staking logic — interest calculations, penalty bypass

The following are **out of scope**:

- Bugs in third-party dependencies (report upstream)
- Social-engineering attacks
- Denial-of-service via resource exhaustion on test/dev instances

## Security Hardening Checklist (Production)

- [ ] Enable TLS for P2P (`[tls] enabled = true, verify_peer = true`)
- [ ] Enable BFT consensus (`[consensus] validator_key_file`, `validator_pubkeys_dir`)
- [ ] Set an API key (`[api] api_key` or `NEXAFLOW_API_KEY` env var)
- [ ] Enable rate limiting (`[api] rate_limit_rpm`)
- [ ] Enable persistence (`[storage] enabled = true`)
- [ ] Use deterministic genesis (`[genesis.accounts]`)
- [ ] Run nodes behind a reverse proxy with HTTPS in production
- [ ] Restrict API bind address to `127.0.0.1` or internal network

## Audit Status

> **Note:** NexaFlow has not yet undergone a formal third-party security audit.
> Use appropriate caution when deploying with real funds.
