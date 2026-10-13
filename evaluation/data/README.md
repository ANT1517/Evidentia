# Evaluation data

| Path | Contents | Committed? |
|---|---|---|
| `examples_synthetic.jsonl` | 11 wholly synthetic records that demonstrate the format. All `provisional`, authored by one person, no splits assigned. **Not an evaluation set.** | yes |
| `private/`, `raw/` | Any non-synthetic or unreviewed text while it is being sanitised. | **no** (git-ignored) |
| `*.private.jsonl`, `*.local.jsonl` | Local working files. | **no** (git-ignored) |

Do not add a large corpus here to reach a count. Add records only when each has provenance,
a licence, sanitised text and a stated label status; then run:

```bash
python scripts/validate_eval_dataset.py evaluation/data/<file>.jsonl --profile starter
```

See `docs/evaluation_dataset_spec.md` and `docs/annotation_guide.md`.
