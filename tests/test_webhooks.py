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
    assert "json" in kwargs
    # Payload should contain Mutagen report details
    payload = kwargs["json"]
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
    mock_post.return_value.status_code = 200

    import hashlib
    import hmac
    import json

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

    payload = kwargs["json"]
    expected_payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    expected_sig = hmac.new(secret.encode('utf-8'), expected_payload_bytes, hashlib.sha256).hexdigest()

    assert sent_sig == expected_sig

