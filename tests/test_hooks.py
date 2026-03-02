"""Tests for the hooks (smart contracts) module."""

import pytest

from nexaflow_core.hooks import (
    HooksManager,
    HookDefinition,
    InstalledHook,
    HookResult,
    HookOn,
    HookState,
    MAX_HOOKS_PER_ACCOUNT,
    MAX_STATE_ENTRIES,
)


@pytest.fixture
def hooks():
    return HooksManager()


class TestHookDefinitionRegistration:
    def test_register_definition(self, hooks):
        ok, msg, defn = hooks.register_definition(
            creator="rAuthor",
            wasm_hex="00112233",
            namespace="test",
        )
        assert ok is True
        assert defn is not None
        assert defn.creator == "rAuthor"
        assert defn.namespace == "test"
        assert len(defn.hook_hash) > 0

    def test_register_duplicate_same_params(self, hooks):
        ok1, _, d1 = hooks.register_definition("rAuthor", wasm_hex="abc", namespace="ns")
        ok2, _, d2 = hooks.register_definition("rAuthor", wasm_hex="abc", namespace="ns")
        # Same params → same hash → already registered
        assert ok2 is False


class TestHookInstallation:
    def test_set_hook(self, hooks):
        ok1, _, defn = hooks.register_definition("rAuthor", wasm_hex="code1",
                                                   namespace="ns")
        ok2, msg2 = hooks.set_hook("rAlice", 0, defn.hook_hash)
        assert ok2 is True

    def test_set_hook_unknown_hash(self, hooks):
        ok, msg = hooks.set_hook("rAlice", 0, "unknown_hash")
        assert ok is False

    def test_max_hooks_per_account(self, hooks):
        defs = []
        for i in range(MAX_HOOKS_PER_ACCOUNT):
            ok, _, d = hooks.register_definition(f"rAuthor{i}",
                                                   wasm_hex=f"code{i}",
                                                   namespace=f"ns{i}")
            defs.append(d)
            hooks.set_hook("rAlice", i, d.hook_hash)
        # All 4 slots full — no room
        ok5, _, d5 = hooks.register_definition("rExtraAuthor", wasm_hex="extra",
                                                 namespace="overflow")
        ok6, msg6 = hooks.set_hook("rAlice", 4, d5.hook_hash)
        assert ok6 is False  # position 4 is out of range

    def test_delete_hook(self, hooks):
        ok1, _, defn = hooks.register_definition("rAuthor", wasm_hex="del1",
                                                   namespace="ns")
        hooks.set_hook("rAlice", 0, defn.hook_hash)
        ok2, msg2 = hooks.delete_hook("rAlice", 0)
        assert ok2 is True
        assert len(hooks.get_hooks("rAlice")) == 0


class TestHookExecution:
    def test_execute_hooks_accept(self, hooks):
        ok1, _, defn = hooks.register_definition("rAuthor", wasm_hex="exec1",
                                                   namespace="ns")
        hooks.set_hook("rAlice", 0, defn.hook_hash)
        # Default execution: no code callable → accept
        all_ok, results = hooks.execute_hooks("rAlice", {"tx_type": 0})
        assert all_ok is True
        assert all(r.result == HookResult.ACCEPT for r in results)

    def test_execute_no_hooks(self, hooks):
        all_ok, results = hooks.execute_hooks("rNobody", {"tx_type": 0})
        assert all_ok is True
        assert len(results) == 0

    def test_execute_after_hooks(self, hooks):
        ok1, _, defn = hooks.register_definition("rAuthor", wasm_hex="after1",
                                                   namespace="ns")
        hooks.set_hook("rAlice", 0, defn.hook_hash, hook_on=HookOn.AFTER)
        all_ok, results = hooks.execute_hooks("rAlice", {"tx_type": 0},
                                               hook_on=HookOn.AFTER)
        assert len(results) == 1


class TestHookState:
    def test_get_hook_state(self, hooks):
        ok1, _, defn = hooks.register_definition("rAuthor", wasm_hex="state1",
                                                   namespace="ns")
        hooks.set_hook("rAlice", 0, defn.hook_hash)
        state = hooks.get_hook_state("rAlice", defn.hook_hash)
        assert state is not None

    def test_hook_state_set_get(self):
        state = HookState()
        state.set("key1", b"value1")
        assert state.get("key1") == b"value1"

    def test_hook_state_delete(self):
        state = HookState()
        state.set("key1", b"value1")
        state.delete("key1")
        assert state.get("key1") is None


class TestHookQueries:
    def test_get_hooks(self, hooks):
        ok1, _, d1 = hooks.register_definition("rA1", wasm_hex="q1",
                                                 namespace="ns1")
        ok2, _, d2 = hooks.register_definition("rA2", wasm_hex="q2",
                                                 namespace="ns2")
        hooks.set_hook("rAlice", 0, d1.hook_hash)
        hooks.set_hook("rAlice", 1, d2.hook_hash)
        result = hooks.get_hooks("rAlice")
        assert len(result) == 2


class TestHookDict:
    def test_installed_hook_to_dict(self, hooks):
        ok1, _, defn = hooks.register_definition("rAuthor", wasm_hex="dict1",
                                                   namespace="ns")
        hooks.set_hook("rAlice", 0, defn.hook_hash, parameters={"p": "v"})
        result = hooks.get_hooks("rAlice")
        assert len(result) == 1
        d = result[0]
        assert d["hook_hash"] == defn.hook_hash
        assert d["account"] == "rAlice"
