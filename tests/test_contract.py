from engine import Assessment, Channel, NormalizedMessage, RiskBand, analyze


def test_stub_returns_valid_assessment():
    msg = NormalizedMessage(external_id="m1", channel=Channel.EMAIL, sender="a@b.com")
    result = analyze(msg)
    assert isinstance(result, Assessment)
    assert result.external_id == "m1"


def test_stub_never_reports_unchecked_as_low():
    msg = NormalizedMessage(external_id="m2", channel=Channel.SMS)
    assert analyze(msg).risk_band == RiskBand.INSUFFICIENT_DATA


def test_every_reason_points_to_existing_evidence():
    result = analyze(NormalizedMessage(external_id="m3", channel=Channel.WHATSAPP))
    known = {e.evidence_id for e in result.evidence}
    for reason in result.reasons:
        assert set(reason.evidence_ids) <= known


def test_assessment_round_trips_through_json():
    result = analyze(NormalizedMessage(external_id="m4", channel=Channel.EMAIL))
    assert Assessment.model_validate_json(result.model_dump_json()) == result
