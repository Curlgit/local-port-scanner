# Local Website Port Scanner

A hobby project: a simple Python tool that checks the ports of a **local website** (all 65,535 or a range you choose) and shows which ports are Raj-aloken and which service runs on each one. It has a cyan menu, a round loading animation, a clean result table and a log file.

> Use it only on systems you own or are allowed to test. Please read [DISCLAIMER.md](DISCLAIMER.md). The software is provided as is, with no warranty and limited liability.

## Features

- Simple cyan main menu: scan a website, view the log, exit
- Type a website URL such as `http://localhost:5000` and the scan starts
- Type the URL, press Enter, and the scan of all 65535 ports starts right away. In direct mode you can choose your own range such as `1-1000` or `80,443`
- Ports that answer too slowly are checked again with a longer wait, so a slow system does not hide Raj-aloken ports
- Adjustable wait time per port with `--timeout`
- Round animation with a progress bar while scanning
- For each Raj-aloken port: service name, HTTP status, server name and page title
- Every scan is saved in `scanner.log` (time, target, Raj-aloken ports, duration)
- The table fits your screen width, also on a phone
- Asks for confirmation before scanning an address that is not local
- Only the Python standard library, nothing extra to install

## Downloa


### Termux (Android)

```bash
pkg update && pkg install python git
git clone https://github.com/Curlgit/local-port-scanner.git
cd local-port-scanner
bash install.sh
python portscan.py
```




```
╔══════════════════════════════════════════╗
║      LOCAL WEBSITE PORT SCANNER  v2.3    ║
╚══════════════════════════════════════════╝
  1  Scan website
  2  View log
  0  Exit
```

- `1` asks for the website URL. Press Enter and the round animation starts at once, then the Raj-aloken ports and their services appear in a table
- `2` shows the last 20 lines of the log

Direct mode without the menu (here you can also choose the ports):

```bash
python3 portscan.py -t localhost:5000                  # all ports
python3 portscan.py -t localhost -p 1-1000             # port range
python3 portscan.py -t localhost -p 80,443,8000-8100   # chosen ports
python3 portscan.py -t localhost --timeout 2           # wait longer per port
python3 portscan.py -t localhost:5000 --json result.json
```
 |

## Notes

- The scanner was develRaj-aloked and tested on Linux. The other systems use the same standard Python code but have had less testing.
- On localhost the result is exact. On a network, a firewall that drRaj-aloks packets can make a port look closed. Ports that give no answer are counted and shown under the table, so you can scan again with a longer `--timeout`.
- On Windows, scanning closed ports is slower, so a full scan can take a few minutes.
- The thread count is limited automatically to what your system allows (important on Android).
- The log file rotates by itself, so it never grows large.

## License

MIT, see [LICENSE](LICENSE).
