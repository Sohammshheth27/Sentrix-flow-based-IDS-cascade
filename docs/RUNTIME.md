# Runtime operations

## Starting and stopping

- Start: `python run.py` or `bash scripts/start_vm_engine.sh`.
- Stop: Ctrl+C or `bash scripts/stop.sh`.

## Persistent storage

The engine writes to a small set of on-disk files under the deployment root:

- `alerts.db`: SQLite database of fused alerts. One row per alert, with the canonical 5-tuple, severity, predicted family, MITRE ATT&CK tactic, source engine, verdict, and per-signal contributing scores.
- `incidents.db`: multi-alert incident grouping by source IP.
- `known_devices.db`: asset inventory plus OUI-derived vendor/OS inference.
- `ueba_long_state.json`: running per-device behavioural baselines (six features). Reloaded on engine restart so the 14-day learning window is preserved across maintenance restarts.
- `logs/`: runtime engine logs, plus Zeek `conn.log` / protocol logs and Suricata `eve.json`.

The dashboard reads exclusively from these files plus the engine's real-time event channel.

## Per-deployment fine-tuning

The cascade exposes five fine-tuning surfaces, applied in order of operator-effort:

1. Self-learned allowlist promotion (round 1): public benign destinations contacted by multiple internal hosts. Promoted nightly via cron.
2. Operator allowlist (round 2): verified cloud-service ranges in `config/whitelist.json`.
3. Threat-intelligence inclusion-list refresh (round 3): edits to `config/ti_exclusions.json`.
4. Operator-supplied policy rules (round 4): explicit policy entries in `config/security_policies.json`.
5. Active-learning loop (round 5): operator triage decisions in the dashboard feed `learn_fp_patterns.py` overnight; learned suppression patterns become runtime suppressions.

## Alert triage

Open the dashboard at port 8080. The Live Alerts table is the canonical analyst-triage view. Per-flow MITRE attribution, source engine (Sentrix or Suricata), and tag are surfaced inline. Use the verdict buttons to mark false positives; the active-learning loop incorporates these decisions on the next nightly run.
