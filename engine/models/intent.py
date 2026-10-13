"""OPTIONAL, ISOLATED adapter: four yes/no intent predictions from a Laya typed-decisions model.

Read this before using it.

* It is NOT part of the verdict pipeline. `analyze()` does not import it, and nothing here can
  change a risk band, override a rule, or trigger an action. It only returns numbers.
* It is DISABLED unless constructed with `enabled=True`.
* The outputs are RAW model probabilities. They are not calibrated, they are not a verdict, and
  the 5B smoke test showed they sit in a narrow band and can be moved by instructions embedded
  in the text (docs/intent_model_suitability.md). Treat them as research signals only.
* Message text is untrusted data. It is truncated, passed once to the model, and never logged,
  stored, printed, or returned. The model is an encoder with typed heads: it generates no
  text, calls no tools and follows no instructions.
* Weights are loaded only from an already-cached, pinned revision, hash-checked, with
  network downloads impossible by construction (`local_files_only=True`).
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import math
import os
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

MODEL_ID = "Ankit1106/laya-typed-decisions"
MODEL_REVISION = "66172d2dfdd5d5c31f0aa5cc999ed2cf2f4b78a2"
WEIGHTS_SHA256 = "59627bc3f726abb45eac3508e322225f498200a79d21286e7369183a659f38c6"
LAYA_VERSION = "0.4.6"
_FILES = ("model.safetensors", "rl_agent_config.json", "encoder/config.json",
          "tokenizer/tokenizer.json", "tokenizer/tokenizer_config.json")

QUESTION_IDS = ("authority_claim_in_content", "payment_request", "credential_request",
                "urgency_secrecy")
QUESTIONS = {
    "authority_claim_in_content": {"type": "noul", "instructions":
        "Does the message claim to come from an executive, senior leader, or other authority figure?"},
    "payment_request": {"type": "noul", "instructions":
        "Does the message ask the recipient to make a payment, wire transfer, invoice payment, "
        "buy gift cards, or change bank account details?"},
    "credential_request": {"type": "noul", "instructions":
        "Does the message ask the recipient to provide credentials, passwords, authentication "
        "codes, or sensitive account information?"},
    "urgency_secrecy": {"type": "noul", "instructions":
        "Does the message create urgency, demand secrecy, or pressure the recipient to bypass "
        "normal procedures?"},
}
DEFAULT_MAX_CHARS = 2000
DEFAULT_TIMEOUT_S = 60.0


class IntentStatus(str, Enum):
    OK = "ok"
    DISABLED = "disabled"                  # adapter not enabled; nothing was run
    EMPTY_INPUT = "empty_input"            # no content: never scored, never defaulted to "no"
    UNAVAILABLE = "unavailable"            # library or pinned weights missing / failed to load
    MALFORMED_OUTPUT = "malformed_output"  # model ran but output could not be validated
    INFERENCE_ERROR = "inference_error"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class IntentResult:
    """Never contains message text. `probabilities` is None unless status is OK."""
    status: IntentStatus
    probabilities: Optional[dict] = None     # question id -> raw P(yes) in [0, 1]
    model_id: str = MODEL_ID
    revision: str = MODEL_REVISION
    detail: str = ""                         # fixed vocabulary / exception type name only
    truncated: bool = False
    calibrated: bool = field(default=False, init=False)   # always False: see module docstring

    @property
    def ok(self) -> bool:
        return self.status is IntentStatus.OK


def parse_answers(result) -> Optional[dict]:
    """-> {qid: float} if EVERY question has a finite probability in [0, 1], else None.

    All-or-nothing on purpose: a partially valid output is not silently completed.
    """
    answers = result.get("answers") if isinstance(result, dict) else None
    if not isinstance(answers, dict):
        return None
    out = {}
    for q in QUESTION_IDS:
        entry = answers.get(q)
        v = entry.get("noul") if isinstance(entry, dict) else None
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        v = float(v)
        if not (math.isfinite(v) and 0.0 <= v <= 1.0):
            return None
        out[q] = v
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def find_cached_model_dir() -> Optional[Path]:
    """The cached snapshot of the pinned revision, or None. Never touches the network."""
    try:
        from huggingface_hub import snapshot_download
        path = snapshot_download(MODEL_ID, revision=MODEL_REVISION,
                                 allow_patterns=list(_FILES), local_files_only=True)
    except Exception:
        return None
    p = Path(path)
    return p if p.name == MODEL_REVISION else None


class LayaIntentAdapter:
    """Lazy, bounded, side-effect-free intent scorer. Construct once; reuse."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        model_dir: Optional[str] = None,
        predict_fn: Optional[Callable[[str], dict]] = None,
        max_chars: int = DEFAULT_MAX_CHARS,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        verify_weights: bool = True,
    ) -> None:
        if max_chars <= 0 or timeout_s <= 0:
            raise ValueError("max_chars and timeout_s must be positive")
        self.enabled = enabled
        self._model_dir = model_dir
        self._predict_fn = predict_fn          # injected fake in tests; None means real model
        self.max_chars = max_chars
        self.timeout_s = timeout_s
        self._verify = verify_weights
        self._lock = threading.Lock()
        self._load_error: Optional[str] = None
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._inflight: Optional[concurrent.futures.Future] = None

    # ------------------------------------------------------------------ loading (lazy, once)

    def _ensure_loaded(self) -> Optional[str]:
        """-> None when ready, else a fixed reason string."""
        with self._lock:
            if self._predict_fn is not None:
                return None
            if self._load_error is not None:
                return self._load_error
            try:
                self._predict_fn = self._load_real_model()
            except _Unavailable as e:
                self._load_error = str(e)
                return self._load_error
            except Exception as e:                       # corrupt files, library incompatibility
                self._load_error = f"load_failed:{type(e).__name__}"
                return self._load_error
            return None

    def _load_real_model(self) -> Callable[[str], dict]:
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        root = Path(self._model_dir) if self._model_dir else find_cached_model_dir()
        if root is None or not (root / "model.safetensors").is_file():
            raise _Unavailable("weights_not_cached")
        if self._verify and _sha256(root / "model.safetensors") != WEIGHTS_SHA256:
            raise _Unavailable("weights_hash_mismatch")
        try:
            import laya
        except ImportError:
            raise _Unavailable("laya_not_installed") from None
        if getattr(laya, "__version__", None) != LAYA_VERSION:
            raise _Unavailable("laya_version_mismatch")
        agent = laya.load(str(root), device="cpu")

        def predict(text: str) -> dict:
            return agent.predict(text, QUESTIONS)
        return predict

    # ------------------------------------------------------------------ inference

    def classify(self, text: str) -> IntentResult:
        """Score `text`. Never raises; never returns a probability unless it validated."""
        if not self.enabled:
            return IntentResult(IntentStatus.DISABLED, detail="adapter_disabled")
        if not isinstance(text, str) or not text.strip():
            return IntentResult(IntentStatus.EMPTY_INPUT, detail="no_content")

        reason = self._ensure_loaded()
        if reason is not None:
            return IntentResult(IntentStatus.UNAVAILABLE, detail=reason)

        truncated = len(text) > self.max_chars
        bounded = text[: self.max_chars]
        predict = self._predict_fn

        with self._lock:
            if self._inflight is not None and not self._inflight.done():
                return IntentResult(IntentStatus.INFERENCE_ERROR, truncated=truncated,
                                    detail="previous_inference_still_running")
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            self._inflight = self._executor.submit(predict, bounded)
            future = self._inflight

        try:
            raw = future.result(timeout=self.timeout_s)
        except concurrent.futures.TimeoutError:
            return IntentResult(IntentStatus.TIMEOUT, truncated=truncated, detail="timeout")
        except Exception as e:                           # never include the message or its text
            return IntentResult(IntentStatus.INFERENCE_ERROR, truncated=truncated,
                                detail=type(e).__name__)

        parsed = parse_answers(raw)
        if parsed is None:
            return IntentResult(IntentStatus.MALFORMED_OUTPUT, truncated=truncated,
                                detail="invalid_or_missing_answers")
        return IntentResult(IntentStatus.OK, probabilities=parsed, truncated=truncated)


class _Unavailable(Exception):
    pass
