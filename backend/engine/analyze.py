"""STUB - replaced by Member B. Keep the signature stable."""
from datetime import datetime, timezone

from shared.schemas import Assessment, Evidence, NormalizedMessage, Reason


def analyze(msg: NormalizedMessage) -> Assessment:
    t = msg.body_text.lower()
    if not t.strip():  # nothing to check is not safe
        return Assessment(risk_band="INSUFFICIENT_DATA", reasons=[], evidence=[],
                          data_completeness="PARTIAL", model_versions={"engine": "stub"})
    if "password" in t or "bank" in t:
        band, code, text = "URGENT", "CREDENTIAL_REQUEST", "Asks for login or bank details."
    elif "urgent" in t:
        band, code, text = "REVIEW", "URGENCY_CUE", "Uses urgent language."
    else:
        return Assessment(risk_band="LOW", reasons=[], evidence=[], data_completeness="COMPLETE",
                          model_versions={"engine": "stub"})
    ev = Evidence(evidence_id="ev-1", type="keyword", value=code, source="stub",
                  observed_at=datetime.now(timezone.utc), status="found")
    return Assessment(risk_band=band, reasons=[Reason(code=code, text=text, evidence_ids=["ev-1"])],
                      evidence=[ev], data_completeness="COMPLETE", model_versions={"engine": "stub"})
