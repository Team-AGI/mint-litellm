"""본인 확인을 기다리는 호출: 서명된 확인 링크, 안내, 확인될 때까지의 보류."""

import asyncio
import json
from dataclasses import replace

from plugin_helpers import config, request
from test_approval_hold import Clock, statuses
from test_plugin_confirmations import setup

from mint_litellm.control import links
from mint_litellm.plugin.approval_hold import hold_if_confirmation_pending
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import CONFIRMATION_LINK_TTL, evaluate_request
from mint_litellm.types.errors import CONFIRMATION_GUIDANCE
from mint_litellm.types.reason_codes import Reason
from mint_litellm.types.settings import Mode

LINK_KEY = b"k" * 32


def with_link(tmp_path):
    return config(
        tmp_path, mode_ceiling=Mode.ENFORCE, console_url="https://mint.example/", link_key=LINK_KEY
    )


def test_the_refusal_carries_guidance_and_a_signed_confirmation_link(tmp_path):
    h = setup(tmp_path, cfg=with_link(tmp_path))
    result = asyncio.run(evaluate_request(request(arguments={"q": "x"}), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CONFIRMATION_REQUIRED
    body = json.loads(result.error.detail())
    assert body["guidance"] == CONFIRMATION_GUIDANCE
    prefix = "https://mint.example/staff/link/"
    assert body["confirm_link"].startswith(prefix)
    token = body["confirm_link"][len(prefix) :]
    kind, ref = links.parse(LINK_KEY, token)
    assert kind == "confirm" and ref == str(h.snapshots.confirmations[0]["id"])
    assert links.parse(LINK_KEY, token, now=2**31) is None
    assert CONFIRMATION_LINK_TTL == 600
    args_fp = h.snapshots.confirmations[0]["args_fp"]
    assert result.confirmation_wait == ("u1", "srv-1", "search", args_fp)


def test_without_console_settings_only_the_guidance_is_returned(tmp_path):
    h = setup(tmp_path, cfg=config(tmp_path, mode_ceiling=Mode.ENFORCE))
    result = asyncio.run(evaluate_request(request(arguments={"q": "x"}), h.deps))
    body = json.loads(result.error.detail())
    assert body["guidance"] == CONFIRMATION_GUIDANCE and "confirm_link" not in body


def test_env_settings_reach_the_plugin_config():
    env = {
        "MINT_INSTANCE_ID": "i1",
        "MINT_DATABASE_URL": "postgresql://x",
        "MINT_OPA_URL": "http://o",
        "MINT_CONSOLE_URL": " https://mint.example ",
        "MINT_WEBHOOK_HMAC_KEY": "a" * 64,
    }
    cfg = PluginConfig.from_env(env)
    assert cfg.console_url == "https://mint.example" and cfg.link_key is not None


def run_hold(h, seconds, status, clock):
    async def go():
        first = await evaluate_request(request(arguments={"q": "x"}), h.deps)

        async def again(held):
            return await evaluate_request(replace(request(arguments={"q": "x"}), hold=held), h.deps)

        return first, await hold_if_confirmation_pending(
            first, seconds, status, again, sleep=clock.sleep, clock=clock
        )

    return asyncio.run(go())


def test_the_call_is_held_until_the_user_confirms_then_judged_again(tmp_path):
    h = setup(tmp_path, cfg=with_link(tmp_path))
    seen = []

    async def status(wait):
        seen.append(wait)
        return "pending" if len(seen) < 3 else "confirmed"

    first, second = run_hold(h, 60, status, Clock())
    assert not first.allowed
    assert len(seen) == 3 and seen[0] == first.confirmation_wait
    assert len(h.snapshots.confirmations) == 2


def test_no_confirmation_within_the_hold_returns_the_refusal(tmp_path):
    h = setup(tmp_path, cfg=with_link(tmp_path))
    _, second = run_hold(h, 5, statuses("pending"), Clock())
    assert not second.allowed
    assert second.snapshot.stop.reason_code == Reason.CONFIRMATION_REQUIRED


def test_a_zero_hold_does_not_wait(tmp_path):
    h = setup(tmp_path, cfg=with_link(tmp_path))
    clock = Clock()
    first, held = run_hold(h, 0, statuses("pending"), clock)
    assert held is first and clock.sleeps == []
