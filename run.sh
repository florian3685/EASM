#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  EASM Scanner — Launcher (use this, not `python main.py`)
# ════════════════════════════════════════════════════════════════════════
#  Forces the project's .venv interpreter so deps + .env are always loaded.
#  Defaults to running ALL modules including active exploitation.
#
#  Usage:
#    ./run.sh                          # interactive TUI
#    ./run.sh example.com              # scan example.com — ALL modules + exploit
#    ./run.sh example.com --stealth    # add stealth mode
#    ./run.sh example.com --safe       # passive only (no module 11)
#    ./run.sh example.com --fresh      # ignore checkpoint, start over
#    ./run.sh --web                    # shared web console on 0.0.0.0:18080
#    ./run.sh --status                 # show API key status
#    ./run.sh --setup                  # interactive API key setup
#
#  RESUME: by default, if a checkpoint exists for the domain, the scan
#  resumes from where it stopped (Ctrl+C, crash, network drop). Use --fresh
#  to discard it.
# ════════════════════════════════════════════════════════════════════════

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$PROJECT_DIR/.venv/bin/python"

# ── Color output ──
if [ -t 1 ]; then
    RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'; CYN='\033[0;36m'; RST='\033[0m'
else
    RED=''; GRN=''; YEL=''; CYN=''; RST=''
fi

# ── Sanity: venv exists? ──
if [ ! -x "$VENV_PY" ]; then
    echo -e "${RED}✗ .venv not found at $PROJECT_DIR/.venv${RST}"
    echo "  Bootstrap with:"
    echo "    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi

# ── Sanity: deps installed? ──
if ! "$VENV_PY" -c "import dns, httpx, dotenv, bs4" 2>/dev/null; then
    echo -e "${YEL}⚠ Some dependencies are missing — installing now…${RST}"
    "$VENV_PY" -m pip install -q -r "$PROJECT_DIR/requirements.txt"
fi

# ── Sanity: .env exists? ──
if [ ! -f "$PROJECT_DIR/.env" ]; then
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        echo -e "${YEL}⚠ No .env found — copying .env.example. Run './run.sh --setup' to fill keys.${RST}"
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    fi
fi

# ── Subcommands ──
case "${1:-}" in
    --web|web)
        shift || true
        WEB_ARGS=("$@")
        HAS_HOST=0
        HAS_PORT=0
        for arg in "$@"; do
            case "$arg" in
                --host|--host=*) HAS_HOST=1 ;;
                --port|--port=*) HAS_PORT=1 ;;
            esac
        done
        if [ "$HAS_PORT" -eq 0 ]; then
            WEB_ARGS=(--port "${EASM_WEB_PORT:-18080}" "${WEB_ARGS[@]}")
        fi
        if [ "$HAS_HOST" -eq 0 ]; then
            WEB_ARGS=(--host "${EASM_WEB_HOST:-0.0.0.0}" "${WEB_ARGS[@]}")
        fi
        cd "$PROJECT_DIR"
        exec "$VENV_PY" "$PROJECT_DIR/web_app.py" "${WEB_ARGS[@]}"
        ;;
    --status|status)
        exec "$VENV_PY" "$PROJECT_DIR/setup_keys.py" --status
        ;;
    --setup|setup)
        exec "$VENV_PY" "$PROJECT_DIR/setup_keys.py"
        ;;
    -h|--help|help)
        echo "Usage:"
        echo "  ./run.sh                       interactive TUI"
        echo "  ./run.sh <domain>              scan domain — ALL 14 modules + exploit"
        echo "  ./run.sh <domain> --stealth    + jitter & evasion headers"
        echo "  ./run.sh <domain> --safe       passive only, no exploitation (no module 11)"
        echo "  ./run.sh --web                 shared web console on 0.0.0.0:18080"
        echo "  ./run.sh --status              show API key status"
        echo "  ./run.sh --setup               interactive API key setup"
        echo
        "$VENV_PY" "$PROJECT_DIR/main.py" --help
        exit 0
        ;;
esac

# ── No args → interactive TUI ──
if [ $# -eq 0 ]; then
    echo -e "${CYN}▸ Launching interactive TUI…${RST}"
    cd "$PROJECT_DIR"
    exec "$VENV_PY" main.py
fi

# ── First arg = domain, rest = extra flags ──
DOMAIN="$1"
shift

# Defaults: ALL modules incl. active exploitation
MODULES="1,2,3,4,5,6,7,8,9,10,11,12,13,14"
EXTRA_FLAGS=("--exploit")

# Strip --safe (no module 11) if requested
for arg in "$@"; do
    if [ "$arg" = "--safe" ]; then
        MODULES="1,2,3,4,5,6,7,8,9,10,12,13,14"
        EXTRA_FLAGS=()
    fi
done

# Pass through anything that's not --safe
PASS=()
for arg in "$@"; do
    [ "$arg" = "--safe" ] && continue
    PASS+=("$arg")
done

# ── Loud warning when exploit mode is active ──
if [ ${#EXTRA_FLAGS[@]} -gt 0 ]; then
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${RST}"
    echo -e "${RED}║  ⚠  ACTIVE EXPLOITATION ENABLED  ⚠                         ║${RST}"
    echo -e "${RED}║  Module 11 will run live SQLi / XSS / DB-dump attacks.     ║${RST}"
    echo -e "${RED}║  Only run against systems you have written authorization   ║${RST}"
    echo -e "${RED}║  to test. Use --safe to disable.                           ║${RST}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${RST}"
    echo
fi

echo -e "${GRN}▸ Target:${RST}  $DOMAIN"
echo -e "${GRN}▸ Modules:${RST} $MODULES"
echo -e "${GRN}▸ Python:${RST}  $VENV_PY"
echo

cd "$PROJECT_DIR"
exec "$VENV_PY" main.py --domain "$DOMAIN" --modules "$MODULES" "${EXTRA_FLAGS[@]}" "${PASS[@]}"
