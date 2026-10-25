"""Application-owned schemas survive shared persistence without losing brakes."""

import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import pytest
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from signin_window.automation.maintenance import MaintenanceStateStore
from signin_window.state import PrivateStateError


class Reason(StrEnum):
    INTERRUPTED = "interrupted"
    BLOCKED = "blocked"


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Hold(Model):
    hold_id: str
    reason: Reason
    recorded_at: AwareDatetime


class Cooldown(Model):
    reason: Reason
    until: AwareDatetime


class State(Model):
    schema_version: int = 1
    hold: Hold | None = None
    cooldown: Cooldown | None = None
    consecutive_blocks: int = Field(default=0, ge=0)
    last_generation: int = Field(default=0, ge=0)
    last_published_at: AwareDatetime | None = None


@pytest.fixture
def store(tmp_path):
    return MaintenanceStateStore(
        tmp_path,
        state_type=State,
        hold_type=Hold,
        cooldown_type=Cooldown,
        valid_keys=frozenset({"example"}),
        block_cooldowns=(timedelta(hours=2), timedelta(hours=8)),
        utc_now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_existing_hold_watermark_and_attempt_count_survive_adoption(store):
    payload = State(
        hold=Hold(hold_id="hold-existing", reason=Reason.INTERRUPTED, recorded_at=store._utc_now()),
        last_generation=17,
        consecutive_blocks=2,
    )
    path = store.root / "example.json"
    path.write_text(payload.model_dump_json())
    before = path.read_bytes()
    assert store.load("example") == payload
    assert path.read_bytes() == before
    assert not store.clear_hold("example", "stale-id")
    assert store.load("example").hold.hold_id == "hold-existing"
    store.record_publish("example", 18)
    assert store.load("example").hold == payload.hold
    assert store.load("example").last_generation == 18
    assert json.loads(path.read_text()) == store.load("example").model_dump(mode="json")
    assert path.stat().st_mode & 0o077 == 0


def test_acknowledged_provisional_hold_cannot_erase_new_hold(store):
    provisional = store.record_hold("example", Reason.INTERRUPTED)
    assert store.clear_hold("example", provisional.hold_id)
    replacement = store.replace_hold("example", provisional.hold_id, Reason.BLOCKED)
    assert replacement.hold_id != provisional.hold_id
    assert not store.clear_hold("example", provisional.hold_id)
    assert store.load("example").hold == replacement


def test_cooldown_policy_and_monotonic_generation(store):
    for delay in (2, 8, 8):
        assert store.record_block("example", Reason.BLOCKED).until == store._utc_now() + timedelta(hours=delay)
    store.record_publish("example", 2)
    for generation in (2, 1, True):
        with pytest.raises(PrivateStateError, match="generation"):
            store.record_publish("example", generation)
    assert store.load("example").cooldown is None


@pytest.mark.parametrize("data", ['{"hold": "broken"}', '{"unrecognized": true}', "{", '{"last_generation":-1}'])
def test_malformed_state_is_never_replaced_with_empty_state(store, data):
    p = store.root / "example.json"
    p.write_text(data)
    with pytest.raises(PrivateStateError):
        store.record_hold("example", Reason.INTERRUPTED)
    assert p.read_text() == data


def test_unowned_key_and_symlink_fail_closed(store, tmp_path):
    with pytest.raises(PrivateStateError):
        store.load("../example")
    other = tmp_path / "other"
    other.write_text("{}")
    (tmp_path / "example.json").symlink_to(other)
    with pytest.raises(PrivateStateError):
        store.load("example")
    assert other.read_text() == "{}"
