#!/usr/bin/env python3
"""
Local Website Port Scanner v2.3

Checks the ports of a website you own (all 65535 by default, or a range you
choose) and shows which ports are open and which service runs on each one. Every scan is saved in a log file.

Run:   python3 portscan.py                          -> menu
       python3 portscan.py -t localhost:5000        -> all ports
       python3 portscan.py -t localhost -p 1-1000   -> port range
       python3 portscan.py -t localhost -p 80,443 --timeout 2
       python3 portscan.py -t localhost --json out.json

Only the Python standard library is used (Python 3.7+).
Use it on your own systems only (see DISCLAIMER.md).
"""
import argparse
import errno
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

try:
    import resource  # not available on Windows
except ImportError:
    resource = None

VERSION = "2.3"
ALL_PORTS = list(range(1, 65536))

# colors (cyan theme)
C, G, Y, R, B, D, N = ("\033[96m", "\033[92m", "\033[93m", "\033[91m",
                       "\033[1m", "\033[2m", "\033[0m")

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}

NOTES = {
    21: "FTP is not encrypted",
    23: "Telnet is not encrypted",
    445: "SMB should stay inside your network",
    3306: "MySQL should stay inside your network",
    3389: "RDP should stay inside your network",
    5432: "PostgreSQL should stay inside your network",
    6379: "Redis should be protected with a password",
    27017: "MongoDB should be protected with a password",
}

IS_TTY = sys.stdout.isatty()

if os.name == "nt":
    os.system("")  # lets Windows terminals show colors

# errno values meaning "out of local resources", not "port closed"
_RETRY_ERRNOS = tuple(
    getattr(errno, n) for n in ("EMFILE", "ENFILE", "ENOBUFS", "EAGAIN")
    if hasattr(errno, n)
)


# ---------- logging ----------
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.log")
log = logging.getLogger("portscan")


def setup_logging():
    """Write scan history to scanner.log (next to the script, or in the home folder)."""
    global LOG_FILE
    log.setLevel(logging.INFO)
    if log.handlers:
        return
    home_log = os.path.join(os.path.expanduser("~"), "scanner.log")
    for path in (LOG_FILE, home_log):
        try:
            handler = RotatingFileHandler(path, maxBytes=200000, backupCount=2,
                                          encoding="utf-8")
        except OSError:
            continue
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
        log.addHandler(handler)
        LOG_FILE = path
        return
    log.addHandler(logging.NullHandler())


def show_log(lines=20):
    print(f"{C}{B}  SCAN LOG{N}  {D}{LOG_FILE}{N}\n")
    try:
        with open(LOG_FILE, encoding="utf-8", errors="replace") as fh:
            last = fh.read().splitlines()[-lines:]
    except OSError:
        last = []
    if not last:
        print(f"  {Y}No log entries yet. Run a scan first.{N}\n")
        return
    for line in last:
        print("  " + line)
    print()


# ---------- helpers ----------
def resolve_target(text):
    """Accept a URL or host. Return (host, ip)."""
    text = text.strip()
    if not text:
        raise ValueError("empty target")
    if "://" not in text:
        text = "http://" + text
    host = urlparse(text).hostname
    if not host:
        raise ValueError("cannot read host from URL")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"cannot resolve '{host}'")
    return host, ip


def is_local(ip):
    a = ipaddress.ip_address(ip)
    return a.is_loopback or a.is_private


def parse_ports(text):
    """'1-1000' or '80,443,8000-8100' -> sorted list of ports."""
    ports = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                ports.update(range(a, b + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"'{part}' is not a valid port or range")
    if not ports:
        raise ValueError("no ports given")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def safe_threads(want=500):
    """Never use more threads than the system allows open sockets."""
    if resource:
        try:
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft != resource.RLIM_INFINITY:
                return max(32, min(want, soft - 64))
        except (ValueError, OSError):
            pass
    return want


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def check_port(ip, port, timeout):
    """True = open, False = closed, None = no answer in time.
    Retries when the system is short on sockets, so no port is skipped by mistake."""
    for _ in range(8):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return False
        except socket.timeout:
            return None
        except OSError as e:
            if e.errno in _RETRY_ERRNOS:
                time.sleep(0.05)
                continue
            return False
    return False


def http_info(host, port, timeout, use_tls):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            # local sites often use self-signed certificates
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        request = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                   f"User-Agent: LocalPortScan/{VERSION}\r\nConnection: close\r\n\r\n")
        sock.sendall(request.encode())
        data = b""
        while len(data) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
    except Exception:
        return None
    text = data.decode("utf-8", errors="replace")
    if not text.startswith("HTTP/"):
        return None
    status = text.split("\r\n", 1)[0].strip()
    server = re.search(r"(?im)^server:\s*(.+)$", text)
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    return {
        "status": status,
        "server": server.group(1).strip() if server else "",
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:60] if title else "",
    }


def read_greeting(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(128).decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def describe_port(ip, port, timeout):
    """Find out which service runs on a port that is already known to be open."""
    t = max(timeout, 1.0)
    info = {"port": port, "service": service_name(port), "http": None,
            "greeting": "", "tls": False}
    http = http_info(ip, port, t, use_tls=False)
    if http is None:
        http = http_info(ip, port, t, use_tls=True)
        if http:
            info["tls"] = True
    if http:
        info["http"] = http
        if info["tls"]:
            info["service"] = "https"
        elif info["service"] == "unknown":
            info["service"] = "http"
    else:
        info["greeting"] = read_greeting(ip, port, t)
    if port in NOTES:
        info["note"] = NOTES[port]
    return info


# ---------- round animation ----------
class Spinner:
    FRAMES = "◐◓◑◒"

    def __init__(self, status):
        self.status = status  # callable -> (label, done, total)
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self.start = time.time()

    def _run(self):
        i = 0
        while not self._stop.is_set():
            label, done, total = self.status()
            pct = int(done * 100 / total) if total else 100
            filled = int(20 * pct / 100)
            bar = "█" * filled + "░" * (20 - filled)
            sys.stdout.write(
                f"\r{C}{B}{self.FRAMES[i % len(self.FRAMES)]}{N} {C}{label:<24}"
                f"{bar} {pct:>3}%{N}  {D}{time.time() - self.start:4.1f}s{N}  ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.06)

    def __enter__(self):
        if IS_TTY:
            self._t.start()
        else:
            print("Scanning ...")
        return self

    def __exit__(self, *a):
        self._stop.set()
        if IS_TTY:
            self._t.join()
            sys.stdout.write("\r" + " " * 78 + "\r")
            sys.stdout.flush()


# ---------- scanning ----------
def run_scan(ip, ports, timeout=None, threads=None):
    """Scan the given ports. Ports that give no answer in time are checked
    once more with a 3x longer timeout, so a slow system does not hide ports."""
    if timeout is None:
        timeout = 0.3 if ipaddress.ip_address(ip).is_loopback else 0.6
    threads = threads or safe_threads()
    ports = list(ports)
    st = {"label": "Scanning ports", "done": 0, "total": len(ports)}
    lock = threading.Lock()

    def run_pool(plist, t):
        def one(p):
            try:
                return p, check_port(ip, p, t)
            finally:
                with lock:
                    st["done"] += 1
        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            return list(ex.map(one, plist))

    start = time.time()
    results = []
    no_answer = 0
    with Spinner(lambda: (st["label"], st["done"], st["total"])):
        states = run_pool(ports, timeout)
        open_ports = [p for p, s in states if s is True]
        slow = [p for p, s in states if s is None]
        if slow and len(slow) <= 2000:
            st.update(label="Re-checking slow ports", done=0, total=len(slow))
            again = run_pool(slow, timeout * 3)
            open_ports += [p for p, s in again if s is True]
            no_answer = sum(1 for p, s in again if s is None)
        else:
            no_answer = len(slow)
        open_ports = sorted(open_ports)
        if open_ports:
            st.update(label="Detecting services", done=0, total=len(open_ports))

            def probe(p):
                try:
                    return describe_port(ip, p, timeout)
                finally:
                    with lock:
                        st["done"] += 1

            with ThreadPoolExecutor(max_workers=min(32, len(open_ports))) as ex:
                results = list(ex.map(probe, open_ports))
    results.sort(key=lambda r: r["port"])
    return {
        "ip": ip,
        "scanned": len(states),
        "total": len(ports),
        "no_answer": no_answer,
        "open": results,
        "seconds": round(time.time() - start, 2),
    }


def scan_and_show(host, ip, ports=None, timeout=None):
    """Run a scan, write it to the log, print the table."""
    ports = ports or ALL_PORTS
    log.info("scan started | target=%s ip=%s ports=%d", host, ip, len(ports))
    try:
        result = run_scan(ip, ports, timeout)
    except Exception as e:
        log.error("scan failed | target=%s error=%s", host, e)
        print(f"{R}Scan failed:{N} {e}")
        return None
    result["target"] = host
    found = ",".join(str(r["port"]) for r in result["open"]) or "none"
    log.info("scan finished | target=%s scanned=%d/%d open=%d (%s) no_answer=%d time=%ss",
             host, result["scanned"], result["total"], len(result["open"]),
             found, result["no_answer"], result["seconds"])
    print_table(result, host)
    return result


# ---------- output ----------
def detail_text(r):
    if r["http"]:
        h = r["http"]
        m = re.match(r"HTTP/\S+\s+(.*)", h["status"])
        parts = [m.group(1) if m else h["status"]]
        if h["server"]:
            parts.append(h["server"])
        if h["title"]:
            parts.append(f'"{h["title"]}"')
        return " | ".join(parts)
    if r["greeting"]:
        return "reply: " + r["greeting"].replace("\n", " ")[:50]
    return "-"


def print_table(result, target_label):
    rows = result["open"]
    pct = int(result["scanned"] * 100 / result["total"]) if result["total"] else 100
    print()
    print(f"{C}{B}  RESULT: {target_label}  ({result['ip']}){N}")
    if not rows:
        print(f"\n  {Y}No open ports found.{N}")
    else:
        cols = ["PORT", "STATE", "SERVICE", "DETAILS"]
        data = []
        for r in rows:
            svc = r["service"] + (" (TLS)" if r["tls"] and r["service"] != "https" else "")
            data.append([f"{r['port']}/tcp", "open", svc, detail_text(r)])
        widths = [max(len(cols[i]), *(len(row[i]) for row in data)) for i in range(4)]
        term = shutil.get_terminal_size((80, 24)).columns
        widths[3] = max(12, min(widths[3], term - 13 - sum(widths[:3])))

        def cut(s, w):
            return s if len(s) <= w else s[: w - 1] + "…"

        def line(l, m, r_):
            return C + l + m.join("─" * (w + 2) for w in widths) + r_ + N

        print(line("┌", "┬", "┐"))
        print(f"{C}│{N}" + f"{C}│{N}".join(
            f" {C}{B}{cols[i].ljust(widths[i])}{N} " for i in range(4)) + f"{C}│{N}")
        print(line("├", "┼", "┤"))
        for row in data:
            cells = [
                f" {G}{row[0].ljust(widths[0])}{N} ",
                f" {G}{row[1].ljust(widths[1])}{N} ",
                f" {C}{row[2].ljust(widths[2])}{N} ",
                f" {cut(row[3], widths[3]).ljust(widths[3])} ",
            ]
            print(f"{C}│{N}" + f"{C}│{N}".join(cells) + f"{C}│{N}")
        print(line("└", "┴", "┘"))
        for r in rows:
            if r.get("note"):
                print(f"  {Y}Note, port {r['port']}: {r['note']}{N}")
    print(f"\n  {C}{len(rows)} open  |  {result['scanned']}/{result['total']} "
          f"ports scanned ({pct}%)  |  {result['seconds']}s{N}")
    if result.get("no_answer"):
        print(f"  {Y}{result['no_answer']} ports gave no answer in time (firewall or slow "
              f"system). Try a longer wait: --timeout 2{N}")
    print()


# ---------- menu ----------
def banner():
    if IS_TTY:
        os.system("cls" if os.name == "nt" else "clear")
    print(f"""{C}{B}╔══════════════════════════════════════════╗
║      LOCAL WEBSITE PORT SCANNER  v{VERSION}    ║
╚══════════════════════════════════════════╝{N}
{C}  1  Scan website
  2  View log
  0  Exit{N}
""")


def ask_target():
    print(f"{C}{B}Enter website URL{N} {D}(example: http://localhost:5000){N}")
    try:
        text = input(f"{C}URL > {N}").strip()
    except EOFError:
        return None
    if not text:
        return None
    try:
        host, ip = resolve_target(text)
    except ValueError as e:
        log.warning("bad target | input=%s error=%s", text, e)
        print(f"{R}Error:{N} {e}")
        return "error"
    if not is_local(ip):
        print(f"{Y}Warning:{N} {ip} is not a local or private address.")
        try:
            ok = input("Do you own this system or have permission to scan it? (yes/no): ")
        except EOFError:
            ok = ""
        if ok.strip().lower() != "yes":
            log.info("scan cancelled | target=%s ip=%s (not local)", host, ip)
            print("Scan cancelled.")
            return "error"
    return host, ip


def pause():
    try:
        input(f"{D}Press Enter to continue...{N}")
    except EOFError:
        pass


def menu():
    while True:
        banner()
        try:
            choice = input(f"{C}Select option > {N}").strip()
        except EOFError:
            print()
            return 0
        if choice == "0":
            print("Bye!")
            return 0
        if choice == "2":
            print()
            show_log()
            pause()
            continue
        if choice != "1":
            print(f"{R}Invalid option.{N}")
            pause()
            continue
        t = ask_target()
        if t is None:
            continue
        if t == "error":
            pause()
            continue
        print()
        scan_and_show(t[0], t[1])
        pause()


# ---------- direct mode ----------
def cli(args):
    try:
        host, ip = resolve_target(args.target)
    except ValueError as e:
        log.warning("bad target | input=%s error=%s", args.target, e)
        print(f"{R}Error:{N} {e}")
        return 2
    if not is_local(ip):
        print(f"{Y}Warning:{N} {ip} is not a local or private address. "
              "Scan only systems you are allowed to test.")
    try:
        ports = parse_ports(args.ports) if args.ports else ALL_PORTS
    except ValueError as e:
        print(f"{R}Error:{N} {e}")
        return 2
    if args.timeout is not None and not 0 < args.timeout <= 30:
        print(f"{R}Error:{N} --timeout must be between 0 and 30 seconds")
        return 2
    result = scan_and_show(host, ip, ports, args.timeout)
    if result is None:
        return 1
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"Saved: {args.json}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Local website port scanner (no arguments = menu)")
    ap.add_argument("-t", "--target", help="website URL or host (direct scan, no menu)")
    ap.add_argument("-p", "--ports", help="ports to scan, e.g. 1-1000 or 80,443 (default: all)")
    ap.add_argument("--timeout", type=float, help="seconds to wait per port (default 0.3 local, 0.6 network)")
    ap.add_argument("--json", metavar="FILE", help="save the result as JSON (with -t)")
    args = ap.parse_args()
    setup_logging()
    if args.target:
        return cli(args)
    try:
        return menu()
    except KeyboardInterrupt:
        print("\nBye!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
