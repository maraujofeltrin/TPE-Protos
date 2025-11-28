#!/usr/bin/env bash
set -euo pipefail

# run.sh - helper to build and run the echo server
# Usage:
#   ./run.sh        # build and start server (foreground output via tee, backgrounded)
#   ./run.sh stop   # stop the running server (uses server.pid)

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

BIN="${ROOT_DIR}/build/bin/socks5d"
LOG_DIR="${ROOT_DIR}/logs"
PIDFILE="${LOG_DIR}/server.pid"
LOGFILE="${LOG_DIR}/server.log"

if [ "${1-}" = "stop" ]; then
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE")
        echo "Stopping server pid=$pid..."
        kill "$pid" || true
        rm -f "$PIDFILE"
        echo "Stopped."
    else
        echo "No pidfile found ($PIDFILE). Is the server running?"
    fi
    exit 0
fi

if [ ! -x "$BIN" ]; then
    echo "Binary not found or not executable: $BIN" >&2
    echo "Run 'make server' first to build the server." >&2
    exit 1
fi

echo "Starting server (logging to $LOGFILE)"
# ensure log dir exists
mkdir -p "$LOG_DIR"
# stop any previous instance that might still be running
pkill -f "$BIN" || true

# start server, pipe stderr+stdout to log and background
export ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:print_stats=1:log_path=./logs/asan"
export LSAN_OPTIONS="print_suppressions=0:log_path=./logs/lsan"
nohup "$BIN" 2>&1 | tee "$LOGFILE" &
srv_pid=$!
echo "$srv_pid" > "$PIDFILE"
echo "Server started with pid $srv_pid"
echo "To stop: ./run.sh stop"

exit 0
