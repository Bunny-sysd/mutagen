import json
from unittest.mock import patch

from mutagen.reporter import save_crash_report


@patch("requests.post")
def test_webhook_alert_firing(mock_post):
    # Set return value for mock
    mock_post.return_value.status_code = 200

    save_crash_report(
        crashes=[{"args": ["test"], "vuln_type": "buffer_overflow", "cwe": "CWE-120", "severity": "critical", "crash_type": "SIGSEGV", "reason": "Overflow test"}],
        target_name="test_webhook",
        total_tested=1,
        webhook_url="http://example.com/webhook"
    )

    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert args[0] == "http://example.com/webhook"
    # The report is sent as pre-serialized bytes via data=, not json= (see
    # test_webhook_body_matches_signed_bytes for why: letting requests
    # independently re-serialize a json= dict produces different bytes than
    # whatever was signed for X-Mutagen-Signature, silently breaking
    # signature verification on the receiving end).
    assert "data" in kwargs
    payload = json.loads(kwargs["data"])
    assert payload["target"] == "test_webhook"
    assert payload["total_crashes_found"] == 1


@patch("requests.post")
def test_run_fuzzer_webhook_propagation(mock_post):
    from mutagen.core import run_fuzzer
    mock_post.return_value.status_code = 200

    # Run in static mode with a mock engine so we don't hit live APIs
    with patch("mutagen.core.get_engine") as mock_get_engine:
        mock_engine = mock_get_engine.return_value
        mock_engine.generate_payloads.return_value = [
            {"args": ["foo"], "input_data": "", "vuln_type": "CWE-120", "severity": "high"}
        ]

        run_fuzzer(
            source_path="targets/01_buffer_overflow.c",
            api_key="mock",
            gcc_path="gcc",
            max_payloads=1,
            timeout=1,
            debug=False,
            static_only=True,
            webhook_url="http://mock-webhook.local"
        )

        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert args[0] == "http://mock-webhook.local"


@patch("requests.post")
def test_webhook_signature_calculation(mock_post):
    """
    The signature must be verifiable against the bytes actually sent on the
    wire (kwargs["data"]), not against a dict that a receiver never sees
    directly. A prior version of this test recomputed the expected signature
    from kwargs["json"] using the exact same compact-separator serialization
    the (buggy) implementation used to sign -- so it could never catch a
    mismatch between what was signed and what was actually transmitted,
    since it was really just checking the code against a copy of itself.
    """
    mock_post.return_value.status_code = 200

    import hashlib
    import hmac

    secret = "my_super_webhook_secret_key"

    save_crash_report(
        crashes=[{"args": ["test"], "vuln_type": "buffer_overflow", "cwe": "CWE-120", "severity": "critical", "crash_type": "SIGSEGV", "reason": "Overflow test"}],
        target_name="test_webhook_sig",
        total_tested=1,
        webhook_url="http://example.com/webhook",
        webhook_secret=secret
    )

    assert mock_post.called
    args, kwargs = mock_post.call_args
    headers = kwargs["headers"]

    assert "X-Mutagen-Signature" in headers
    sent_sig = headers["X-Mutagen-Signature"]

    actual_wire_bytes = kwargs["data"]
    expected_sig = hmac.new(secret.encode('utf-8'), actual_wire_bytes, hashlib.sha256).hexdigest()

    assert sent_sig == expected_sig


@patch("requests.post")
def test_webhook_body_matches_signed_bytes_through_real_requests_serialization(mock_post):
    """
    Regression test: the implementation used to sign a compact
    json.dumps(report, separators=(',', ':')) serialization but send the
    report via requests.post(..., json=report), which makes the `requests`
    library independently re-serialize the dict -- with different key/comma
    spacing than what was signed. Any receiver that does the standard,
    correct thing (recompute HMAC-SHA256 over the raw bytes it actually
    received) would always see a mismatch, silently breaking
    --webhook-secret for every real webhook receiver. This test builds the
    real request via requests.Request(...).prepare() (not a mock) to verify
    against the actual bytes that would go over the wire.
    """
    import hashlib
    import hmac

    import requests

    mock_post.return_value.status_code = 200
    secret = "my_super_webhook_secret_key"

    save_crash_report(
        crashes=[{"args": ["test"], "vuln_type": "buffer_overflow", "cwe": "CWE-120", "severity": "critical", "crash_type": "SIGSEGV", "reason": "Overflow test"}],
        target_name="test_webhook_wire",
        total_tested=1,
        webhook_url="http://example.com/webhook",
        webhook_secret=secret
    )

    args, kwargs = mock_post.call_args
    sent_sig = kwargs["headers"]["X-Mutagen-Signature"]

    # Build the real HTTP request exactly as requests.post() would, to get
    # the true wire body -- not a mock's copy of whatever kwargs were passed.
    prepared = requests.Request("POST", args[0], **{k: v for k, v in kwargs.items() if k in ("data", "json", "headers")}).prepare()
    actual_wire_body = prepared.body
    if isinstance(actual_wire_body, str):
        actual_wire_body = actual_wire_body.encode("utf-8")

    recomputed_sig = hmac.new(secret.encode('utf-8'), actual_wire_body, hashlib.sha256).hexdigest()
    assert sent_sig == recomputed_sig, "signature must verify against the ACTUAL bytes transmitted on the wire"

