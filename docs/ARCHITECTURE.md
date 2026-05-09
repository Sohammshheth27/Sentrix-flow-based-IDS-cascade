# Architecture

Sentrix is a five-layer cascade. The unit of input is an IPFIX-canonicalised network flow.

- Layer 0 (parallel observation): Zeek extracts per-flow connection records and protocol metadata; Suricata runs payload-pattern signatures against the same packet stream. The two engines observe different evidence classes and their false-positive surfaces are orthogonal.
- Layer 1 (feature schema): A canonical 53-feature IPFIX schema, derived from Zeek output, holds feature derivation constant across heterogeneous training corpora. Schema canonicalisation is the precondition on which cross-distribution and zero-shot transfer depend.
- Layer 2 (ML cascade): Stage 1 is a calibrated logit-space ensemble of LightGBM, XGBoost, and Random Forest with grid-searched fusion weights `(0.45, 0.50, 0.05)`. Stage 2 is an 18-class family typer that allocates positive Stage 1 flows to a malware family and a corresponding MITRE ATT&CK tactic.
- Layer 3 (seven-signal fusion): The fused severity score combines the calibrated Stage 1 logit, the Stage 2 family confidence, the threat-intelligence indicator hits, the per-device UEBA deviation, the per-flow context score, the rule-engine score, and the policy score. Fusion is performed in log-odds space; the load-bearing fusion equation is `logit_fused = sum_i w_i * logit(p_i)` and the threat-intelligence augmentation is `logit_TI = beta_0 + beta_ML * z(logit_fused) + beta_match * h_match + beta_avail * h_avail`.
- Layer 4 (alert emission): A four-layer allowlist defence (Tranco static, multi-feed consensus, per-deployment self-learned, operator override) and a per-deployment fine-tuning loop (operator triage; nightly active-learning promotion) gate alert emission. Surviving alerts are persisted to `alerts.db` and pushed to the dashboard.

## Stage 1 mathematical claim

The 5-seed mean AUC on UGR-16 cross-distribution is `0.9414 ± 0.0052`. Per-source threshold tuning subject to `FPR <= 0.01` lifts F1 from `0.012` (default `tau = 0.5`) to `0.2228` (`tau* = 0.07`). Logit-space threat-intelligence fusion lifts F1 further to `0.4114`. The 34x cumulative gain is achieved without retraining.

## Stage 2 mathematical claim

18-class macro-F1 = 0.8842 on the held-out partition. Three cryptominer labels collapse into a single behavioural cluster (label-structure artefact); effective family count is sixteen.

## Operational claim

Per-deployment fine-tuning reduces alert volume from 464 at zero-day deployment to 28 after five rounds (93.97% cumulative reduction) on a 5-hour office capture, with no machine-learning retraining at any round. Integrated with Suricata 7.0.3 (post two-stage filter, 21 actionable alerts), the integrated cascade emits 49 alerts with zero inter-tool overlap on the 5-tuple key.
