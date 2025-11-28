#!/usr/bin/env bash
set -euo pipefail

# run.sh - helper to build and run the SOCKS5 server
# Usage:
#   ./run.sh        # build and start server (output to stdout/stderr)
#   ./run.sh debug  # build and start server (redirect output to log file)
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

# Verificar el modo de ejecución
DEBUG_MODE=false
if [ "${1-}" = "debug" ]; then
    DEBUG_MODE=true
    echo "Starting server in DEBUG mode (logging to $LOGFILE)"
else
    echo "Starting server in NORMAL mode (output to console)"
fi

# ensure log dir exists
mkdir -p "$LOG_DIR"
# stop any previous instance that might still be running
pkill -f "$BIN" || true

# Configurar variables de AddressSanitizer
export ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:print_stats=1:log_path=./logs/asan"
export LSAN_OPTIONS="print_suppressions=0:log_path=./logs/lsan"

if [ "$DEBUG_MODE" = true ]; then
    # Modo debug: redirigir stdout y stderr al archivo de log
    echo "Server output will be redirected to $LOGFILE"
    nohup "$BIN" > "$LOGFILE" 2>&1 &
    srv_pid=$!
    echo "$srv_pid" > "$PIDFILE"
    echo "Server started with pid $srv_pid"
    echo "To view logs: tail -f $LOGFILE"
    echo "To stop: ./run.sh stop"
else
    # Modo normal: salida a la consola
    echo "Server output will be displayed on console (Ctrl+C to stop)"
    "$BIN"
fi

exit 0
