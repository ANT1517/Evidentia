"""Evaluation-dataset tooling (schema, validator, split generation).

Independent of the production engine: nothing here imports `engine`, loads a model, or uses
the network. See docs/evaluation_dataset_spec.md.
"""
from .schema import (
    INTENT_LABELS,
    LABEL_STATUSES,
    OUTCOMES,
    SCENARIOS,
    SCHEMA_VERSION,
    SPLITS,
)

__all__ = ["INTENT_LABELS", "LABEL_STATUSES", "OUTCOMES", "SCENARIOS", "SCHEMA_VERSION", "SPLITS"]
