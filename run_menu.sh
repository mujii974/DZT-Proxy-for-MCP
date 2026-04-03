#!/usr/bin/env bash
# =============================================================
#  DZT Proxy -- Attack Simulation Menu
# =============================================================
#  All secrets (GITHUB_PAT) are loaded from .env -- never hardcoded.
#  Servers are started/stopped automatically per option.
# =============================================================

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$PROJECT_DIR/.env"

# -- Load .env -------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  echo ""
  echo "  ERROR: .env file not found."
  echo "  Copy .env.example to .env and fill in your GITHUB_PAT."
  echo ""
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

# -- Validate PAT if needed -----------------------------------
check_pat() {
  if [ -z "${GITHUB_PAT:-}" ] || [ "$GITHUB_PAT" = "YOUR_GITHUB_PAT_HERE" ]; then
    echo ""
    echo "  ERROR: GITHUB_PAT is not set in .env"
    echo "  Edit .env and add your GitHub Personal Access Token."
    echo ""
    return 1
  fi
  return 0
}

# -- Activate venv ---------------------------------------------
VENV="$PROJECT_DIR/.venv/bin/activate"
if [ -f "$VENV" ]; then
  source "$VENV"
fi

cd "$PROJECT_DIR"
export PYTHONPATH="$PROJECT_DIR"

# -- Run logging -----------------------------------------------
LOG_DIR="$PROJECT_DIR/logs/menu_runs"
mkdir -p "$LOG_DIR"
RUN_TS="$(date +%Y%m%d_%H%M%S)"
RUN_LOG="$LOG_DIR/run_menu_${RUN_TS}.log"

echo "  [i] Live output enabled. Session log: $RUN_LOG"

run_and_log() {
  local label="$1"
  shift
  echo ""
  echo "  [>] $label"
  echo "  [>] CMD: $*"
  {
    echo ""
    echo "===== $label ====="
    echo "CMD: $*"
    echo "TIME: $(date '+%Y-%m-%d %H:%M:%S')"
  } >> "$RUN_LOG"

  if [ -w /dev/tty ]; then
    "$@" 2>&1 | tee -a "$RUN_LOG"
  else
    "$@" 2>&1 | tee -a "$RUN_LOG"
  fi
}

# -- Server PIDs -----------------------------------------------
PROXY_PID=""
BASELINE_PID=""
RUNTIME_MODE=""


choose_runtime() {
  while true; do
    echo ""
    echo "  ============================================================"
    echo "         Runtime Selection"
    echo "  ============================================================"
    echo "   1) uvicorn processes (local Python runtime)"
    echo "   2) Docker Compose containers"
    echo "  ============================================================"
    read -rp "  Choose runtime [1-2]: " runtime_choice

    case "$runtime_choice" in
      1)
        RUNTIME_MODE="uvicorn"
        echo "  [i] Runtime selected: uvicorn"
        return 0
        ;;
      2)
        if ! command -v docker >/dev/null 2>&1; then
          echo "  [!] Docker is not installed or not on PATH."
          continue
        fi
        RUNTIME_MODE="docker"
        echo "  [i] Runtime selected: docker"
        return 0
        ;;
      *)
        echo "  Invalid choice. Please select 1 or 2."
        ;;
    esac
  done
}

# -- Server management -----------------------------------------

cleanup_ports() {
  if [ "$RUNTIME_MODE" = "docker" ]; then
    docker compose down --remove-orphans >/dev/null 2>&1 || true
  else
    fuser -k 8000/tcp 2>/dev/null || true
    fuser -k 8001/tcp 2>/dev/null || true
    rm -f nonces.db server_nonces.db 2>/dev/null || true
    sleep 1
  fi
}

start_baseline() {
  if [ "$RUNTIME_MODE" = "docker" ]; then
    echo "  [+] Starting local MCP server (Docker) on port 8001..."
    docker compose up -d mcp_server >/dev/null
  else
    echo "  [+] Starting local MCP server (no security) on port 8001..."
    uvicorn mcp_server.baseline:app --host 127.0.0.1 --port 8001 \
      > /tmp/dzt_baseline.log 2>&1 &
    BASELINE_PID=$!
  fi
}

start_proxy_local() {
  if [ "$RUNTIME_MODE" = "docker" ]; then
    echo "  [+] Starting DZT Proxy (Docker, secure local) on port 8000..."
    DZT_MODE=secure UPSTREAM_MODE=local docker compose up -d dzt_proxy mcp_server >/dev/null
  else
    echo "  [+] Starting DZT Proxy (secure, local) on port 8000..."
    DZT_MODE=secure UPSTREAM_MODE=local \
      AGENT_PRIVATE_KEY_PATH=did/keys/agent1_private.pem \
      uvicorn dzt_proxy.app:app --host 127.0.0.1 --port 8000 \
      > /tmp/dzt_proxy.log 2>&1 &
    PROXY_PID=$!
  fi
}

start_proxy_github() {
  if [ "$RUNTIME_MODE" = "docker" ]; then
    echo "  [+] Starting DZT Proxy (Docker, secure GitHub MCP) on port 8000..."
    DZT_MODE=secure UPSTREAM_MODE=github docker compose up -d dzt_proxy >/dev/null
  else
    echo "  [+] Starting DZT Proxy (secure, GitHub MCP) on port 8000..."
    DZT_MODE=secure UPSTREAM_MODE=github \
      AGENT_PRIVATE_KEY_PATH=did/keys/agent1_private.pem \
      uvicorn dzt_proxy.app:app --host 127.0.0.1 --port 8000 \
      > /tmp/dzt_proxy.log 2>&1 &
    PROXY_PID=$!
  fi
}

wait_ready() {
  local url="$1"
  local label="$2"
  local timeout=15
  printf "  [~] Waiting for %-30s " "$label..."
  local i=0
  while [ $i -lt $timeout ]; do
    if curl -sf "$url" > /dev/null 2>&1; then
      echo "ready"
      return 0
    fi
    printf "."
    sleep 1
    i=$((i+1))
  done
  echo " TIMEOUT"
  return 1
}

stop_servers() {
  echo ""
  echo "  [-] Stopping servers..."
  if [ "$RUNTIME_MODE" = "docker" ]; then
    docker compose down --remove-orphans >/dev/null 2>&1 || true
    echo "  [-] Docker services stopped."
  else
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null && wait "$PROXY_PID" 2>/dev/null && echo "  [-] Proxy stopped." || true
    [ -n "${BASELINE_PID:-}" ] && kill "$BASELINE_PID" 2>/dev/null && wait "$BASELINE_PID" 2>/dev/null && echo "  [-] Baseline stopped." || true
    fuser -k 8000/tcp 2>/dev/null || true
    fuser -k 8001/tcp 2>/dev/null || true
  fi
  PROXY_PID=""
  BASELINE_PID=""
}

# -- Clean up on exit ------------------------------------------
trap 'stop_servers; exit 0' INT TERM EXIT

# -- Menu ------------------------------------------------------
menu() {
  echo ""
  echo "  ============================================================"
  echo "         DZT Proxy -- Evaluation Menu"
  echo "  ============================================================"
  echo "  Runtime: $RUNTIME_MODE"
  echo ""
  echo "   ATTACK SIMULATION"
  echo "   1)  Local MCP  -- WITHOUT Proxy  (no security)"
  echo "   2)  Local MCP  -- WITH Proxy     (DZT secured)"
  echo "   3)  GitHub MCP -- WITHOUT Proxy  (direct, PAT only)"
  echo "   4)  GitHub MCP -- WITH Proxy     (DZT secured)"
  echo ""
  echo "   EVALUATION"
  echo "   5)  Benign 100 Calls  (false positive rate)"
  echo "   6)  Latency Benchmarks (Local + GitHub, direct vs proxy overhead)"
  echo "   7)  Generate + Print Full Report (5.4 + 5.5 incl. ML tables)"
  echo ""
  echo "   8)  Exit"
  echo "   9)  Switch Runtime (uvicorn/docker)"
  echo ""
  echo "  ============================================================"
  echo ""
  read -rp "  Select option [1-9]: " choice

  case "$choice" in

    # -- Option 1: Local direct (no proxy, no security) --------
    1)
      echo ""
      echo "  -- Attacking Local MCP Server WITHOUT Proxy --"
      cleanup_ports

      start_baseline
      wait_ready "http://127.0.0.1:8001/tools" "Local MCP (8001)" || { stop_servers; return; }

      echo ""
      run_and_log "Option 1: local direct attacks" env UPSTREAM_MODE=local python3 eval/attack_runner.py local_direct

      stop_servers
      ;;

    # -- Option 2: Local through proxy (secured) ---------------
    2)
      echo ""
      echo "  -- Attacking Local MCP Server WITH DZT Proxy --"
      cleanup_ports

      start_baseline
      start_proxy_local

      wait_ready "http://127.0.0.1:8001/tools"  "Local MCP (8001)" || { stop_servers; return; }
      wait_ready "http://127.0.0.1:8000/health"  "DZT Proxy (8000)" || { stop_servers; return; }

      echo ""
      run_and_log "Option 2: local proxy attacks" env UPSTREAM_MODE=local python3 eval/attack_runner.py local_proxy

      stop_servers
      ;;

    # -- Option 3: GitHub direct (no proxy, PAT only) ----------
    3)
      echo ""
      echo "  -- Attacking GitHub MCP Server WITHOUT Proxy --"

      check_pat || return

      echo ""
      run_and_log "Option 3: github direct attacks" env UPSTREAM_MODE=github python3 eval/attack_runner.py github_direct
      ;;

    # -- Option 4: GitHub through proxy (secured) --------------
    4)
      echo ""
      echo "  -- Attacking GitHub MCP Server WITH DZT Proxy --"

      check_pat || return
      cleanup_ports

      start_proxy_github
      wait_ready "http://127.0.0.1:8000/health" "DZT Proxy (8000)" || { stop_servers; return; }

      echo ""
      run_and_log "Option 4: github proxy attacks" env UPSTREAM_MODE=github python3 eval/attack_runner.py github_proxy

      stop_servers
      ;;

    # -- Option 5: Benign 100 calls (false positive rate) ------
    5)
      echo ""
      echo "  -- Benign Workload Test (100 calls, false positive rate) --"
      cleanup_ports

      start_baseline
      start_proxy_local

      wait_ready "http://127.0.0.1:8001/tools"  "Local MCP (8001)" || { stop_servers; return; }
      wait_ready "http://127.0.0.1:8000/health"  "DZT Proxy (8000)" || { stop_servers; return; }

      echo ""
      run_and_log "Option 5: benign test" env UPSTREAM_MODE=local python3 eval/benign_test.py 100

      stop_servers
      ;;

    # -- Option 6: Latency benchmarks (local + github) ---------
    6)
      echo ""
      echo "  -- Latency Benchmarks (local + github, direct vs proxy overhead) --"
      cleanup_ports

      start_baseline
      start_proxy_local

      wait_ready "http://127.0.0.1:8001/tools"  "Local MCP (8001)" || { stop_servers; return; }
      wait_ready "http://127.0.0.1:8000/health"  "DZT Proxy (8000)" || { stop_servers; return; }

      echo ""
      run_and_log "Option 6A: local latency benchmark" env UPSTREAM_MODE=local python3 eval/latency_benchmark.py 30

      stop_servers

      if check_pat; then
        echo ""
        echo "  -- GitHub Latency Benchmark (absolute vs overhead) --"
        cleanup_ports
        start_proxy_github
        wait_ready "http://127.0.0.1:8000/health" "DZT Proxy (8000)" || { stop_servers; return; }

        echo ""
        run_and_log "Option 6B: github latency benchmark" python3 eval/latency_benchmark_github.py 20
        stop_servers
      else
        echo ""
        echo "  [!] Skipping GitHub latency benchmark (PAT not set)."
      fi
      ;;

    # -- Option 7: Generate report-ready sections 5.4 and 5.5 ---
    7)
      echo ""
      echo "  -- Generating and printing full Section 5.4 + 5.5 report --"
      echo ""
      run_and_log "Option 7: generate report sections" python3 eval/generate_tables.py
      run_and_log "Option 7: print full report file" cat eval/results/capstone_tables.txt
      ;;

    # -- Option 8: Exit ----------------------------------------
    8)
      echo ""
      echo "  Goodbye."
      exit 0
      ;;

    # -- Option 9: switch runtime -------------------------------
    9)
      stop_servers
      choose_runtime
      ;;

    *)
      echo "  Invalid option. Choose 1-9."
      ;;

  esac

  echo ""
  read -rp "  Press Enter to return to menu..." _
}

# -- Main loop -------------------------------------------------
choose_runtime
while true; do
  menu
done
