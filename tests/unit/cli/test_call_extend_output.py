from types import SimpleNamespace

from mint_litellm import cli


def test_extend_reports_completion(monkeypatch):
    calls, messages = [], []
    run = SimpleNamespace(
        args=SimpleNamespace(call_approval_id="call-1"),
        context=lambda: "context",
        say=messages.append,
    )
    monkeypatch.setattr(cli.call_approval_service, "extend", lambda *a: calls.append(a))
    cli._call_extend(run)
    assert calls == [("context", "call-1")]
    assert "call-1" in messages[0] and "연장" in messages[0]
