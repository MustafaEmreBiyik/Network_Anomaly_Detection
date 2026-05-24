# Sprint - May 24th, 2025

## Changes Made by Betül

### 1. TTL-Based Automatic Unblock Mechanism (`firewall_manager.py`)

- Added a `blocked_ips` SQLite table (in the existing `alerts.db`) with columns `ip` (primary key) and `blocked_at` (ISO timestamp) to track when each IP was blocked.
- `block_ip()` now records the block timestamp via `_record_block()` on every successful block.
- `unblock_ip()` now removes the tracking record via `_remove_block_record()` on any outcome.
- Added `check_expired_blocks(ttl_seconds=None)` function that iterates all tracked blocked IPs and calls `unblock_ip()` for any whose block duration exceeds the TTL.
- Default TTL is 1 hour (3600 seconds), configurable via the `BLOCK_TTL_SECONDS` environment variable.

### 2. Background TTL Expiry Thread (`app.py`)

- Added a daemon background thread (`_ttl_expiry_loop`) that calls `check_expired_blocks()` every 60 seconds.
- Thread is started once per Streamlit session using a `st.session_state` guard to prevent duplicate threads on rerun.
- Imported `check_expired_blocks` from `firewall_manager` alongside existing imports, with a no-op fallback if the import fails.

### 3. Graduated Response Mechanism (`kafka_consumer.py`)

- Added a sliding-window attack tracker (`_attack_history`) using a `defaultdict(list)` that maps each source IP to a list of detection timestamps.
- Added `_get_escalation(src_ip)` function that prunes entries older than the window, appends the current detection, and returns a graduated action with count:
  - **1st detection**: `ALERT` (log only, no block label)
  - **2nd-3rd detection**: `SUSPICIOUS` (elevated logging)
  - **4th+ detection**: `BLOCKED` (eligible for SOC review)
- Replaced the previous binary `BLOCKED`/`ALLOWED` action logic in `process_message()` with the graduated response for non-whitelisted attack IPs.
- Added `Escalation_Count` column to `CSV_HEADER_COLUMNS` and every CSV log entry.
- Updated database detail string to include escalation context (e.g., `escalation: SUSPICIOUS #3 in 60s window`).
- Updated console output to show the escalation label (e.g., `SUSPICIOUS (#3): VOLUMETRIC DETECTED!`).
- Sliding window size is configurable via the `ESCALATION_WINDOW_SECONDS` environment variable (default: 60 seconds).

## Files Modified

| File | Change |
|------|--------|
| `src/utils/firewall_manager.py` | Added blocked_ips table, block/unblock tracking, `check_expired_blocks()` |
| `src/dashboard/app.py` | Added background TTL expiry thread, imported `check_expired_blocks` |
| `src/kafka_consumer.py` | Added sliding-window tracker, graduated response logic, `Escalation_Count` CSV column |

## New Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCK_TTL_SECONDS` | `3600` | How long (seconds) a firewall block stays active before auto-unblock |
| `ESCALATION_WINDOW_SECONDS` | `60` | Sliding window (seconds) for counting repeated attack detections per IP |
