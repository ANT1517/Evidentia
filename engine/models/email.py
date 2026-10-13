"""OPTIONAL, ISOLATED, EXPERIMENTAL adapter: whole-email class scores from DistilBERT.

Model: cybersectony/phishing-email-detection-distilbert_v2.4.1 at a pinned revision.

* The four output classes are returned BY INDEX ONLY. The label mapping is `unresolved`: the
  model card and the dataset card disagree (docs/email_model_suitability.md) and no authority
  settles it. Nothing here names a class "phishing" or "legitimate".
* It is not part of the verdict pipeline, cannot change a risk band, and is disabled unless
  constructed with `enabled=True`.
* Scores are softmax outputs, not calibrated probabilities. The probe showed false alarms on
  routine mail and degenerate input scored as class 1 at ~1.0, hence empty input is never run.
* Text is untrusted, bounded, never logged or returned. Weights: pinned local safetensors only,
  `local_files_only=True`, `trust_remote_code=False`; a download cannot be initiated here.
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

MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
MODEL_REVISION = "6724dec17360ab1f6450553f1d950404f66a5dde"
WEIGHTS_SHA256 = "42e571f4e66cc6e34f949ebbcc61d7d2299fbfda29d2ebbbcfe11225133e6e71"
LABEL_MAPPING = "unresolved"
NUM_CLASSES = 4
MAX_TOKENS = 512
DEFAULT_MAX_CHARS = 5000
DEFAULT_TIMEOUT_S = 60.0
_FILES = ("config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
          "special_tokens_map.json", "vocab.txt")


class EmailModelStatus(str, Enum):
    OK = "ok"
    DISABLED = "disabled"
    EMPTY_INPUT = "empty_input"
    UNAVAILABLE = "unavailable"
    MALFORMED_OUTPUT = "malformed_output"
    INFERENCE_ERROR = "inference_error"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class EmailClassResult:
    """Never contains message text. `probabilities` is None unless status is OK."""
    status: EmailModelStatus
    probabilities: Optional[tuple] = None        # 4 softmax values, indexed by class
    winning_index: Optional[int] = None
    model_id: str = MODEL_ID
    revision: str = MODEL_REVISION
    label_mapping: str = LABEL_MAPPING           # always "unresolved"
    detail: str = ""
    truncated: bool = False
    experimental: bool = field(default=True, init=False)

    @property
    def ok(self) -> bool:
        return self.status is EmailModelStatus.OK


def validate_probabilities(raw) -> Optional[tuple]:
    """-> 4-tuple of floats, or None. Must be finite, in [0,1], and sum to ~1."""
    try:
        vals = tuple(raw)
    except TypeError:
        return None
    if len(vals) != NUM_CLASSES:
        return None
    out = []
    for v in vals:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        v = float(v)
        if not (math.isfinite(v) and 0.0 <= v <= 1.0):
            return None
        out.append(v)
    return tuple(out) if abs(sum(out) - 1.0) <= 1e-3 else None


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


class _Unavailable(Exception):
    pass


class EmailClassifierAdapter:
    def __init__(
        self,
        *,
        enabled: bool = False,
        model_dir: Optional[str] = None,
        predict_fn: Optional[Callable[[str], object]] = None,
        max_chars: int = DEFAULT_MAX_CHARS,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        verify_weights: bool = True,
    ) -> None:
        if max_chars <= 0 or timeout_s <= 0:
            raise ValueError("max_chars and timeout_s must be positive")
        self.enabled = enabled
        self._model_dir = model_dir
        self._predict_fn = predict_fn          # injected fake in tests: text -> 4 probabilities
        self.max_chars = max_chars
        self.timeout_s = timeout_s
        self._verify = verify_weights
        self._lock = threading.Lock()
        self._load_error: Optional[str] = None
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._inflight: Optional[concurrent.futures.Future] = None

    def _ensure_loaded(self) -> Optional[str]:
        with self._lock:
            if self._predict_fn is not None:
                return None
            if self._load_error is not None:
                return self._load_error
            try:
                self._predict_fn = self._load_real_model()
            except _Unavailable as e:
                self._load_error = str(e)
            except Exception as e:
                self._load_error = f"load_failed:{type(e).__name__}"
            return self._load_error

    def _load_real_model(self) -> Callable[[str], object]:
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        root = Path(self._model_dir) if self._model_dir else find_cached_model_dir()
        if root is None or not (root / "model.safetensors").is_file():
            raise _Unavailable("weights_not_cached")
        if self._verify and _sha256(root / "model.safetensors") != WEIGHTS_SHA256:
            raise _Unavailable("weights_hash_mismatch")
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError:
            raise _Unavailable("dependencies_not_installed") from None
        tok = AutoTokenizer.from_pretrained(root, local_files_only=True)
        model = AutoModelForSequenceClassification.from_pretrained(
            root, local_files_only=True, use_safetensors=True, trust_remote_code=False)
        model.eval()

        def predict(text: str):
            enc = tok(text, truncation=True, max_length=MAX_TOKENS, return_tensors="pt")
            with torch.inference_mode():
                logits = model(**enc).logits[0]
            return torch.softmax(logits, dim=-1).tolist()
        return predict

    def classify(self, text: str) -> EmailClassResult:
        """Never raises; never returns scores unless they validated."""
        S = EmailModelStatus
        if not self.enabled:
            return EmailClassResult(S.DISABLED, detail="adapter_disabled")
        if not isinstance(text, str) or not text.strip():
            return EmailClassResult(S.EMPTY_INPUT, detail="no_content")
        reason = self._ensure_loaded()
        if reason is not None:
            return EmailClassResult(S.UNAVAILABLE, detail=reason)

        truncated = len(text) > self.max_chars
        bounded, predict = text[: self.max_chars], self._predict_fn
        with self._lock:
            if self._inflight is not None and not self._inflight.done():
                return EmailClassResult(S.INFERENCE_ERROR, truncated=truncated,
                                        detail="previous_inference_still_running")
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            self._inflight = self._executor.submit(predict, bounded)
            future = self._inflight
        try:
            raw = future.result(timeout=self.timeout_s)
        except concurrent.futures.TimeoutError:
            return EmailClassResult(S.TIMEOUT, truncated=truncated, detail="timeout")
        except Exception as e:                   # exception type only, never the text
            return EmailClassResult(S.INFERENCE_ERROR, truncated=truncated, detail=type(e).__name__)

        probs = validate_probabilities(raw)
        if probs is None:
            return EmailClassResult(S.MALFORMED_OUTPUT, truncated=truncated,
                                    detail="invalid_class_scores")
        return EmailClassResult(S.OK, probabilities=probs,
                                winning_index=max(range(NUM_CLASSES), key=probs.__getitem__),
                                truncated=truncated)
