import socket

from engine.domains import (
    domain_label,
    edit_distance,
    email_domain,
    host_of,
    registered_domain,
    skeleton,
)


def test_registered_domain_uses_public_suffix_list():
    assert registered_domain("a.b.co.in") == "b.co.in"
    assert registered_domain("x.sbi.co.in") == "sbi.co.in"
    assert registered_domain("mail.microsoft.com") == "microsoft.com"
    assert registered_domain("a.b.example.com.au") == "example.com.au"


def test_unlisted_tld_follows_psl_default_rule():
    assert registered_domain("portal.acmesupplies.example") == "acmesupplies.example"
    assert registered_domain("localhost") == "localhost"


def test_ip_and_empty_are_unchanged():
    assert registered_domain("10.0.0.1") == "10.0.0.1"
    assert registered_domain("") == ""


def test_punycode_is_decoded_to_unicode():
    puny = "microsоft.com".encode("idna").decode("ascii")     # Cyrillic о
    assert puny.startswith("xn--")
    assert registered_domain(puny) == "microsоft.com"


def test_host_of_normalises():
    assert host_of("HTTP://Portal.Example.COM./x") == "portal.example.com"
    assert host_of("not a url") is None


def test_email_domain_and_label():
    assert email_domain("A@Mail.Example.org") == "mail.example.org"
    assert email_domain("nobody") == ""
    assert domain_label("micros0ft-secure.example") == "micros0ft-secure"
    assert domain_label("sbi.co.in") == "sbi"


def test_skeleton_collapses_lookalikes():
    base = skeleton("microsoft")
    assert skeleton("micros0ft") == base
    assert skeleton("rnicrosoft") == base
    assert skeleton("microsоft") == base          # Cyrillic о
    assert skeleton("paypa1") == skeleton("paypal")


def test_edit_distance():
    assert edit_distance("google", "goggle") == 1
    assert edit_distance("abc", "abc") == 0
    assert edit_distance("", "abc") == 3


def test_network_guard_is_active_and_lookups_still_work():
    # conftest blocks sockets; registered_domain must not need the network.
    try:
        socket.getaddrinfo("example.com", 80)
        raised = False
    except AssertionError:
        raised = True
    assert raised
    assert registered_domain("a.b.co.uk") == "b.co.uk"
