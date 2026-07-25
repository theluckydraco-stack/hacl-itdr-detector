# Architecture

The first milestone is a local, deterministic detection pipeline using only synthetic data.

```mermaid
flowchart LR
    A[JSONL authentication events] --> B[Strict parser]
    C[Employee CSV] --> D[Identity parser]
    E[TOML thresholds] --> F[Configuration parser]
    B --> G[Normalised AuthEvent records]
    D --> H[Identity directory]
    F --> I[Sliding-window detector]
    G --> I
    H --> I
    I --> J[Success and lockout correlation]
    J --> K[Severity and confidence scoring]
    K --> L[Structured JSONL alerts]
```

## Boundaries

- The detector does not authenticate users or modify accounts.
- The detector does not change the original hACL allow list.
- The detector does not ingest production healthcare or employee data.
- Thresholds are demonstration defaults, not universal security standards.
- File-integrity monitoring is a later milestone.
