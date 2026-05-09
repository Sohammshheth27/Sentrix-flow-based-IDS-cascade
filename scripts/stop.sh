#!/bin/bash
# stop.sh — tear down all Sentrix processes.
#
# Usage:  bash scripts/stop.sh
#
# Stops dashboard_server, realtime_engine, and capture_flows.
# Leaves Zeek alone (it's a system service — use `sudo zeekctl stop`
# if you also want to stop packet capture).
#
# Idempotent: safe to run multiple times. Always exits 0.

echo "=== Stopping Sentrix processes ==="

# Try graceful TERM first, escalate to KILL if any survive
for pat in 'dashboard_server' 'realtime_engine' 'capture_flows'; do
    if pgrep -f "$pat" >/dev/null 2>&1; then
        echo "  stopping $pat..."
        pkill -TERM -f "$pat" 2>/dev/null || true
    fi
done

sleep 2

for pat in 'dashboard_server' 'realtime_engine' 'capture_flows'; do
    if pgrep -f "$pat" >/dev/null 2>&1; then
        echo "  $pat still alive — force kill"
        pkill -9 -f "$pat" 2>/dev/null || true
    fi
done

sleep 1

# Free port 8080 if anything is still squatting on it
if command -v fuser >/dev/null 2>&1; then
    fuser -k 8080/tcp 2>/dev/null || true
fi

# Verify
REMAINING=$(pgrep -af 'dashboard_server|realtime_engine|capture_flows' \
             | grep -v stop.sh || true)
if [ -n "$REMAINING" ]; then
    echo "WARNING: some processes still running:"
    echo "$REMAINING"
    exit 1
fi

echo "=== STOP_OK — all Sentrix processes stopped ==="
echo
echo "Note: Zeek is still running. To stop it too:"
echo "      sudo /opt/zeek/bin/zeekctl stop"
exit 0
