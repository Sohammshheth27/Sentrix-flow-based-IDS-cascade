#!/bin/bash
# start_vm_engine.sh — start dashboard_server + realtime_engine directly on the VM.
#
# Bypasses run.py's subprocess supervisor (which has a false-crash-detection
# bug when backgrounded via ssh nohup). Each process is launched with
# nohup + setsid + stdin redirected from /dev/null so it survives the
# parent ssh session closing.
#
# Usage:    bash start_vm_engine.sh [--mode zeek|csv] [--csv-file PATH]
# Exit 0 on success, non-zero on failure.

set -u  # undefined var is fatal
MODE="${1:-zeek}"
CSV_FILE="${2:-/home/sohamm/sentrix/data/sanity_500.csv}"
ROWS="${3:-0}"

PROJECT=/home/sohamm/Sentrix VENV=$PROJECT/venv
LOG_DIR=/tmp

cd "$PROJECT" || { echo "FAIL: cd $PROJECT"; exit 1; }
source "$VENV/bin/activate" || { echo "FAIL: venv"; exit 2; }

echo "=== cleanup ==="
pkill -9 -f 'dashboard_server' 2>/dev/null || true
pkill -9 -f 'realtime_engine'  2>/dev/null || true
pkill -9 -f 'run.py'           2>/dev/null || true
sleep 1
# Force port 8080 free
if command -v fuser >/dev/null 2>&1; then
    fuser -k 8080/tcp 2>/dev/null || true
fi
sleep 1
rm -f alerts.db alerts.db-shm alerts.db-wal
rm -f known_devices.db known_devices.db-shm known_devices.db-wal
rm -f rules_state.db rules_state.db-shm rules_state.db-wal
rm -f incidents.db incidents.db-shm incidents.db-wal
rm -f ueba.db ueba.db-shm ueba.db-wal
rm -f ueba_long_state.json
# threat_intel.db is preserved — it's seeded data, not runtime state
rm -f "$LOG_DIR/dashboard.log" "$LOG_DIR/engine.log"

echo "=== starting dashboard_server.py ==="
setsid nohup python -u src/dashboard_server.py \
    > "$LOG_DIR/dashboard.log" 2>&1 < /dev/null &
disown
DASHBOARD_PID=$!
echo "dashboard PID: $DASHBOARD_PID"

# Wait for dashboard to respond on 0.0.0.0:8080
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/summary | grep -q '200'; then
        echo "dashboard HEALTHY (t=${i}s)"
        break
    fi
    if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        echo "FAIL: dashboard process exited during startup"
        echo "--- dashboard.log tail ---"
        tail -40 "$LOG_DIR/dashboard.log"
        exit 3
    fi
    sleep 1
done

# Final health check
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/summary || echo 000)
if [ "$HTTP_CODE" != "200" ]; then
    echo "FAIL: dashboard did not respond with 200 (got $HTTP_CODE)"
    echo "--- dashboard.log tail ---"
    tail -40 "$LOG_DIR/dashboard.log"
    exit 4
fi

echo
echo "=== starting realtime_engine.py ==="
ENGINE_ARGS="--mode $MODE"
if [ "$MODE" = "csv" ]; then
    ENGINE_ARGS="$ENGINE_ARGS --file $CSV_FILE"
    if [ "$ROWS" != "0" ]; then ENGINE_ARGS="$ENGINE_ARGS --rows $ROWS"; fi
elif [ "$MODE" = "zeek" ]; then
    ENGINE_ARGS="$ENGINE_ARGS --zeek-dir /opt/zeek/logs/current"
fi

setsid nohup python -u src/realtime_engine.py $ENGINE_ARGS \
    > "$LOG_DIR/engine.log" 2>&1 < /dev/null &
disown
ENGINE_PID=$!
echo "engine PID: $ENGINE_PID"

# Wait for "Engine ready" marker or process exit
for i in $(seq 1 40); do
    if grep -q "Engine ready" "$LOG_DIR/engine.log" 2>/dev/null; then
        echo "engine READY (t=${i}s)"
        break
    fi
    if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
        echo "FAIL: engine process exited during startup"
        echo "--- engine.log tail ---"
        tail -40 "$LOG_DIR/engine.log"
        exit 5
    fi
    sleep 1
done

if ! grep -q "Engine ready" "$LOG_DIR/engine.log"; then
    echo "FAIL: engine did not reach 'Engine ready' marker within 40s"
    echo "--- engine.log tail ---"
    tail -60 "$LOG_DIR/engine.log"
    exit 6
fi

echo
echo "=== READY ==="
echo "dashboard PID: $DASHBOARD_PID  (http://$(hostname -I | awk '{print $1}'):8080)"
echo "engine PID:    $ENGINE_PID     (mode=$MODE)"
echo "dashboard log: $LOG_DIR/dashboard.log"
echo "engine log:    $LOG_DIR/engine.log"
echo "START_VM_ENGINE_OK"
exit 0
