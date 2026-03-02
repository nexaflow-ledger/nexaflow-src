"""
Hooks (Smart Contracts) for NexaFlow.

A simplified hooks engine inspired by the XRPL Hooks amendment:
  - SetHook: install, update, or delete a hook on an account
  - Hooks execute before (or after) transactions on the hooked account
  - Hooks can accept, reject, or modify transaction processing
  - Each hook is a Python callable (simulating WASM in production)

Hook lifecycle:
  1. Author registers a HookDefinition (code hash + parameters)
  2. Account installs a hook via SetHook transaction
  3. On each incoming/outgoing transaction, installed hooks run
  4. Hooks return ACCEPT or REJECT
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class HookResult(Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    ROLLBACK = "rollback"


class HookOn(Enum):
    """When the hook fires."""
    BEFORE = "before"
    AFTER = "after"


@dataclass
class HookDefinition:
    """A registered hook definition (code template)."""
    hook_hash: str
    creator: str
    code: Callable | None = None   # Python callable for simulation
    wasm_hex: str = ""              # placeholder for real WASM
    namespace: str = ""
    parameters: dict[str, str] = field(default_factory=dict)
    hook_on: int = 0xFFFFFFFF       # bitmask of tx types to fire on (all by default)
    grant_accounts: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "hook_hash": self.hook_hash,
            "creator": self.creator,
            "namespace": self.namespace,
            "parameters": self.parameters,
            "hook_on": self.hook_on,
            "grants": self.grant_accounts,
        }


@dataclass
class InstalledHook:
    """A hook installed on a specific account."""
    account: str
    position: int  # 0-3 (max 4 hooks per account)
    hook_hash: str
    parameters: dict[str, str] = field(default_factory=dict)
    hook_on: HookOn = HookOn.BEFORE

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "position": self.position,
            "hook_hash": self.hook_hash,
            "parameters": self.parameters,
            "hook_on": self.hook_on.value,
        }


@dataclass
class HookExecution:
    """Record of a hook execution during a transaction."""
    hook_hash: str
    account: str
    result: HookResult
    return_code: int = 0
    return_string: str = ""
    emit_count: int = 0
    execution_index: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "hook_hash": self.hook_hash,
            "account": self.account,
            "result": self.result.value,
            "return_code": self.return_code,
            "return_string": self.return_string,
            "emit_count": self.emit_count,
        }


@dataclass
class HookState:
    """Key-value state storage for a hook on an account."""
    entries: dict[str, bytes] = field(default_factory=dict)

    def get(self, key: str) -> bytes | None:
        return self.entries.get(key)

    def set(self, key: str, value: bytes) -> None:
        self.entries[key] = value

    def delete(self, key: str) -> bool:
        if key in self.entries:
            del self.entries[key]
            return True
        return False


MAX_HOOKS_PER_ACCOUNT = 4
MAX_STATE_ENTRIES = 256
MAX_STATE_KEY_LEN = 32
MAX_STATE_VALUE_LEN = 256


class HookContext:
    """
    Context object passed to hook callables during execution.
    Provides access to transaction data, hook state, and emitting.
    """

    def __init__(self, tx_data: dict, account: str,
                 hook_hash: str, state: HookState,
                 parameters: dict[str, str]):
        self.tx_data = tx_data
        self.account = account
        self.hook_hash = hook_hash
        self.state = state
        self.parameters = parameters
        self._emitted: list[dict] = []
        self.return_code = 0
        self.return_string = ""

    def get_tx_field(self, field: str) -> Any:
        return self.tx_data.get(field)

    def get_state(self, key: str) -> bytes | None:
        return self.state.get(key)

    def set_state(self, key: str, value: bytes) -> bool:
        if len(key) > MAX_STATE_KEY_LEN:
            return False
        if len(value) > MAX_STATE_VALUE_LEN:
            return False
        if len(self.state.entries) >= MAX_STATE_ENTRIES and key not in self.state.entries:
            return False
        self.state.set(key, value)
        return True

    def emit(self, tx_dict: dict) -> bool:
        """Emit a new transaction from the hook."""
        if len(self._emitted) >= 3:  # max 3 emitted txns per hook
            return False
        self._emitted.append(tx_dict)
        return True

    def accept(self, msg: str = "", code: int = 0) -> HookResult:
        self.return_string = msg
        self.return_code = code
        return HookResult.ACCEPT

    def reject(self, msg: str = "", code: int = 0) -> HookResult:
        self.return_string = msg
        self.return_code = code
        return HookResult.REJECT

    def rollback(self, msg: str = "", code: int = 0) -> HookResult:
        self.return_string = msg
        self.return_code = code
        return HookResult.ROLLBACK


class HooksManager:
    """Manages hook definitions, installations, and execution."""

    def __init__(self):
        self.definitions: dict[str, HookDefinition] = {}
        self.installed: dict[str, list[InstalledHook | None]] = {}  # account -> [4 slots]
        self.state: dict[str, dict[str, HookState]] = {}  # account -> {hook_hash: state}
        self.executions: list[HookExecution] = []

    @staticmethod
    def _hash_code(code_str: str) -> str:
        return hashlib.sha256(code_str.encode()).hexdigest()[:40]

    def register_definition(self, creator: str,
                            code: Callable | None = None,
                            wasm_hex: str = "",
                            namespace: str = "",
                            parameters: dict[str, str] | None = None,
                            hook_on: int = 0xFFFFFFFF,
                            grant_accounts: list[str] | None = None
                            ) -> tuple[bool, str, HookDefinition | None]:
        """Register a hook definition."""
        code_repr = wasm_hex or (code.__name__ if code else "empty")
        hh = self._hash_code(f"{creator}:{code_repr}:{namespace}")

        if hh in self.definitions:
            return False, "Hook already registered", None

        defn = HookDefinition(
            hook_hash=hh,
            creator=creator,
            code=code,
            wasm_hex=wasm_hex,
            namespace=namespace,
            parameters=parameters or {},
            hook_on=hook_on,
            grant_accounts=grant_accounts or [],
        )
        self.definitions[hh] = defn
        return True, "Hook registered", defn

    def set_hook(self, account: str, position: int,
                 hook_hash: str,
                 parameters: dict[str, str] | None = None,
                 hook_on: HookOn = HookOn.BEFORE) -> tuple[bool, str]:
        """Install a hook on an account at the given position (0-3)."""
        if position < 0 or position >= MAX_HOOKS_PER_ACCOUNT:
            return False, f"Position must be 0-{MAX_HOOKS_PER_ACCOUNT - 1}"
        if hook_hash not in self.definitions:
            return False, "Hook definition not found"

        slots = self.installed.setdefault(account, [None] * MAX_HOOKS_PER_ACCOUNT)
        slots[position] = InstalledHook(
            account=account,
            position=position,
            hook_hash=hook_hash,
            parameters=parameters or {},
            hook_on=hook_on,
        )
        # Initialize state
        self.state.setdefault(account, {}).setdefault(hook_hash, HookState())
        return True, "Hook installed"

    def delete_hook(self, account: str, position: int) -> tuple[bool, str]:
        """Remove a hook from an account."""
        slots = self.installed.get(account)
        if slots is None or position >= len(slots):
            return False, "No hook at position"
        if slots[position] is None:
            return False, "Slot already empty"
        slots[position] = None
        return True, "Hook removed"

    def execute_hooks(self, account: str, tx_data: dict,
                      hook_on: HookOn = HookOn.BEFORE
                      ) -> tuple[bool, list[HookExecution]]:
        """
        Execute all hooks for an account matching the hook_on phase.
        Returns (all_accepted, executions).
        If any hook rejects, the transaction should be rejected.
        """
        slots = self.installed.get(account, [])
        results: list[HookExecution] = []
        all_accepted = True

        for idx, hook in enumerate(slots):
            if hook is None:
                continue
            if hook.hook_on != hook_on:
                continue

            defn = self.definitions.get(hook.hook_hash)
            if defn is None:
                continue

            # Check hook_on bitmask for tx type
            tx_type = tx_data.get("tx_type", 0)
            if defn.hook_on != 0xFFFFFFFF:
                if not (defn.hook_on & (1 << tx_type)):
                    continue

            state = self.state.setdefault(account, {}).setdefault(
                hook.hook_hash, HookState())
            ctx = HookContext(
                tx_data=tx_data,
                account=account,
                hook_hash=hook.hook_hash,
                state=state,
                parameters={**defn.parameters, **hook.parameters},
            )

            try:
                if defn.code is not None:
                    result = defn.code(ctx)
                    if not isinstance(result, HookResult):
                        result = HookResult.ACCEPT
                else:
                    result = HookResult.ACCEPT
            except Exception as e:
                result = HookResult.ROLLBACK
                ctx.return_string = str(e)

            execution = HookExecution(
                hook_hash=hook.hook_hash,
                account=account,
                result=result,
                return_code=ctx.return_code,
                return_string=ctx.return_string,
                emit_count=len(ctx._emitted),
                execution_index=idx,
            )
            results.append(execution)
            self.executions.append(execution)

            if result in (HookResult.REJECT, HookResult.ROLLBACK):
                all_accepted = False

        return all_accepted, results

    def get_hooks(self, account: str) -> list[dict]:
        """Get installed hooks for an account."""
        slots = self.installed.get(account, [])
        return [h.to_dict() for h in slots if h is not None]

    def get_hook_state(self, account: str, hook_hash: str) -> dict:
        """Get hook state entries."""
        state = self.state.get(account, {}).get(hook_hash)
        if state is None:
            return {}
        return {k: v.hex() for k, v in state.entries.items()}

    def get_recent_executions(self, limit: int = 50) -> list[dict]:
        return [e.to_dict() for e in self.executions[-limit:]]
