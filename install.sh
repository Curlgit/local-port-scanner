#!/usr/bin/env bash
# Local Website Port Scanner - installer (Linux, macOS, Termux)
# Usage:  bash install.sh
set -u
cd "$(dirname "$0")" || exit 1

C='\033[96m'; G='\033[92m'; Y='\033[93m'; R='\033[91m'; N='\033[0m'
ok()   { printf "${G}[ok]${N} %s\n" "$1"; }
warn() { printf "${Y}[!]${N} %s\n" "$1"; }
fail() { printf "${R}[x]${N} %s\n" "$1"; exit 1; }

printf "${C}== Local Website Port Scanner - installer ==${N}\n"

# 1) Python 3 (the scanner needs nothing else)
if ! command -v python3 >/dev/null 2>&1; then
  warn "python3 not found, trying to install it..."
  if [ -d "/data/data/com.termux" ]; then
    pkg install -y python || fail "could not install python in Termux"
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y python3 || fail "apt install failed"
  elif command -v brew >/dev/null 2>&1; then
    brew install python || fail "brew install failed"
  else
    fail "please install Python 3.7+ manually, then run this script again"
  fi
fi

python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" \
  || fail "Python 3.7 or newer is required"
ok "Python $(python3 -c 'import platform; print(platform.python_version())') found"

# 2) Check the script and set permissions
[ -f portscan.py ] || fail "portscan.py not found next to install.sh"
python3 -c "import ast; ast.parse(open('portscan.py', encoding='utf-8').read())" \
  || fail "portscan.py has a syntax error"
chmod +x portscan.py install.sh 2>/dev/null
ok "portscan.py checked"

printf "\n${G}Install complete.${N}\n\n"
cat <<'USAGE'
Start the scanner (menu):
    python3 portscan.py

    1  Scan website   (enter a URL, for example http://localhost:5000)
    2  View log
    0  Exit

Direct mode (no menu):
    python3 portscan.py -t localhost:5000
    python3 portscan.py -t localhost:5000 --json result.json

Quick test website (open a second terminal):
    python3 -m http.server 8000
    then scan  http://localhost:8000

Every scan is saved in scanner.log (same folder).
USAGE
