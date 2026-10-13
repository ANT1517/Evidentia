import base64
import hashlib
from pathlib import Path

import pytest

from engine.parser import parse_email
from engine.schemas import Channel

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return parse_email((FIX / name).read_bytes(), external_id=name)


def test_legit_vendor_headers_and_auth():
    m = load("legit_vendor.eml")
    assert m.channel == Channel.EMAIL
    assert m.sender == "billing@acmesupplies.example"
    assert m.sender_display_name == "Acme Supplies Billing"
    assert m.reply_to == ""
    assert m.subject == "Invoice 4471 due Friday"
    assert (m.auth.spf, m.auth.dkim, m.auth.dmarc) == ("pass", "pass", "pass")


def test_legit_vendor_urls_have_no_trailing_punctuation():
    m = load("legit_vendor.eml")
    assert m.urls == ["https://portal.acmesupplies.example/invoices/4471"]
    assert m.link_mismatches == []
    assert m.attachments == []


def test_credential_phish_html_is_flattened_and_safe():
    m = load("credential_phish.eml")
    assert "alert(1)" not in m.body_text
    assert "color:red" not in m.body_text
    assert "<" not in m.body_text
    assert "password expires today" in m.body_text
    assert (m.auth.spf, m.auth.dkim, m.auth.dmarc) == ("fail", "none", "fail")


def test_credential_phish_detects_link_text_vs_href_mismatch():
    m = load("credential_phish.eml")
    assert len(m.link_mismatches) == 1
    mm = m.link_mismatches[0]
    assert mm.shown_domain == "microsoft.com"
    assert mm.href_domain == "micros0ft-secure.example"
    assert "http://micros0ft-secure.example/login?u=priya" in m.urls
    assert "http://other-host.example/reset" in m.urls


def test_bec_reply_to_and_no_urls():
    m = load("bec_reply_to.eml")
    assert m.sender == "rajesh.kumar@ourcompany.example"
    assert m.reply_to == "rajesh.kumar.ceo@gmail.example"
    assert m.sender_display_name == "Rajesh Kumar (CEO)"
    assert m.urls == []
    assert "bank account" in m.body_text


def test_attachment_is_hashed_never_opened():
    m = load("malicious_attachment.eml")
    assert len(m.attachments) == 1
    a = m.attachments[0]
    assert a.filename == "invoice.pdf.exe"
    data = base64.b64decode(
        "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    assert a.size == len(data)
    assert a.sha256 == hashlib.sha256(data).hexdigest()
    assert "Please find the invoice attached" in m.body_text


def test_missing_auth_headers_are_none_not_pass():
    m = load("malicious_attachment.eml")
    assert (m.auth.spf, m.auth.dkim, m.auth.dmarc) == (None, None, None)


def test_encoded_headers_and_received_spf_fallback():
    m = load("encoded_headers.eml")
    assert m.sender_display_name == "Rajesh Kumar – CEO"
    assert m.subject == "Café invoice – urgent"
    assert m.auth.spf == "softfail"
    assert m.auth.dkim is None
    assert m.urls == ["http://example.org/pay"]


@pytest.mark.parametrize(
    "raw",
    [b"", b"not an email at all", b"From: \xff\xfe\nSubject: \x00\n\n\xc3\x28"],
)
def test_garbage_input_never_raises(raw):
    m = parse_email(raw, external_id="g")
    assert m.external_id == "g"
    assert m.urls == []
