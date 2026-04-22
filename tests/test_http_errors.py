"""BitSealLedger._format_http_error: verifies the error message shape the
SDK surfaces to users. This is the last line of defense before a raw HTTP
error reaches the user, so regressions here degrade UX silently.
"""

from unittest.mock import MagicMock

from BitSealCore import BitSealLedger


def _mock_response(status_code: int, json_body=None, text: str = "", raises_on_json: bool = False):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if raises_on_json or json_body is None:
        resp.json.side_effect = ValueError("not JSON")
    else:
        resp.json.return_value = json_body
    return resp


def test_json_error_field_surfaces():
    ledger = BitSealLedger()
    resp = _mock_response(400, {"error": "manifest size_bytes missing"})
    msg = ledger._format_http_error(resp)
    assert "400" in msg
    assert "size_bytes missing" in msg


def test_json_message_field_fallback():
    ledger = BitSealLedger()
    resp = _mock_response(422, {"message": "validation failed on leaf count"})
    msg = ledger._format_http_error(resp)
    assert "422" in msg
    assert "validation failed on leaf count" in msg


def test_rate_limit_includes_retry_after():
    # The 429 branch intentionally omits the status code in favor of a
    # user-friendly "retry after ~Ns" phrasing — keep that contract.
    ledger = BitSealLedger()
    resp = _mock_response(429, {"error": "Too many requests", "retry_after_seconds": 42})
    msg = ledger._format_http_error(resp)
    assert "Too many requests" in msg
    assert "42" in msg
    assert "retry" in msg.lower()


def test_non_json_response_falls_back_to_text():
    ledger = BitSealLedger()
    resp = _mock_response(502, raises_on_json=True, text="Bad Gateway")
    msg = ledger._format_http_error(resp)
    assert "502" in msg
    assert "Bad Gateway" in msg


def test_empty_body_shows_status_only():
    ledger = BitSealLedger()
    resp = _mock_response(500, raises_on_json=True, text="")
    msg = ledger._format_http_error(resp)
    assert "500" in msg


def test_long_text_body_truncated():
    ledger = BitSealLedger()
    huge = "Lorem " * 1000
    resp = _mock_response(503, raises_on_json=True, text=huge)
    msg = ledger._format_http_error(resp)
    assert "503" in msg
    assert len(msg) < 1000  # truncation keeps it terminal-friendly
