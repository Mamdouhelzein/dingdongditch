# DingDongDitch 🔔

> Knocks on every port, finds out who answers, and tells you which doors should never have been open.

![CI](https://github.com/Mamdouhelzein/dingdongditch/actions/workflows/ci.yml/badge.svg)
![status](https://img.shields.io/badge/status-early%20development-orange)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A port scanner written from scratch in Python. It finds open TCP ports, works out which service and version is behind each one, and proves common misconfigurations without exploiting anything.

**Status:** the scanner works. The machine learning part, which will predict which CVEs are most likely to be exploited, isn't built yet, so the Risk column only shows confirmed problems for now.

## What it looks like

A real scan of a Metasploitable 2 lab VM:

```
$ dingdongditch scan 192.168.195.130 -p 21,22,80,1524,3306 --karen-mode

                                       Open services
┌─────────────────┬──────────┬───────────┬─────────────────────────┬───────────────────────┐
│ Host            │ Port     │ Service   │ Product / version       │ Risk                  │
├─────────────────┼──────────┼───────────┼─────────────────────────┼───────────────────────┤
│ 192.168.195.130 │ 21/tcp   │ ftp       │ vsftpd 2.3.4            │ CONFIRMED             │
│ 192.168.195.130 │ 22/tcp   │ ssh       │ OpenSSH 4.7p1           │ model not trained yet │
│ 192.168.195.130 │ 80/tcp   │ http      │ Apache httpd 2.2.8      │ model not trained yet │
│                 │          │           │ Metasploitable2 - Linux │                       │
│ 192.168.195.130 │ 1524/tcp │ bindshell │ bindshell               │ CONFIRMED             │
│ 192.168.195.130 │ 3306/tcp │ mysql     │ MySQL 5.0.51a           │ model not trained yet │
└─────────────────┴──────────┴───────────┴─────────────────────────┴───────────────────────┘
OS guess for 192.168.195.130: Ubuntu
  from port 22 (ssh): Ubuntu; port 80 (http): Ubuntu; port 3306 (mysql): Ubuntu
CONFIRMED 192.168.195.130:21 Anonymous FTP login allowed
  Why: Anyone can log in to this FTP server without an account.
  Fix: Disable anonymous access, e.g. anonymous_enable=NO in vsftpd.conf.
CONFIRMED 192.168.195.130:1524 Open shell with no login
  Why: Anyone who connects gets a command prompt on this machine with no password. This is usually a backdoor.
  Fix: Find and stop whatever is listening on this port, and treat the machine as compromised until you know how it got there.
```

## Install

You need Python 3.10 or newer. It isn't on PyPI yet, so install it from GitHub with [pipx](https://pipx.pypa.io/):

```bash
pipx install git+https://github.com/Mamdouhelzein/dingdongditch.git
```

Run the same command with `--force` to update. On Linux this also installs the manual:

```bash
man dingdongditch
```

nmap is optional. You only need it for `--engine nmap`.

## Usage

Only scan machines you own or have written permission to test.

```bash
dingdongditch scan 192.168.195.130                  # default ports (about 1,100)
dingdongditch scan 192.168.195.130 -P quick         # about 100 common ports
dingdongditch scan 192.168.195.130 -P full          # all 65,535 ports
dingdongditch scan 192.168.195.130 -p 22,80,443     # exact ports
dingdongditch scan 192.168.195.130 -p 8000-9000     # a range
dingdongditch scan 10.0.0.1,10.0.0.2                # several hosts
dingdongditch scan 192.168.195.0/24 -P quick        # a whole subnet
dingdongditch scan 192.168.195.130 --karen-mode     # every port, every safe check
dingdongditch scan 192.168.195.130 --json           # JSON instead of a table
```

| Option | What it does | Default |
|---|---|---|
| `-P`, `--profile` | How many ports: `quick`, `default` or `full` | `default` |
| `-p`, `--ports` | Exact ports, such as `22,80` or `8000-9000` | |
| `--karen-mode` | All ports plus every extra check | off |
| `-t`, `--timeout` | Seconds to wait for each port | `1.0` |
| `-c`, `--concurrency` | Ports to try at once | `500` |
| `-e`, `--engine` | `own` (built in) or `nmap` | `own` |
| `-o`, `--save` | Also save the results to a file | |
| `--json` | Print JSON instead of a table | off |

Already have an nmap report? Read it the same way:

```bash
dingdongditch analyze scan.xml
nmap -sV -oX - 192.168.195.130 | dingdongditch analyze -
```

**Finding fewer ports than you expected?** It's probably going too fast for that machine or network. Slow it down with `-c 100 -t 3`.

## Karen mode

`--karen-mode` demands to speak to every port's manager.

| | Normal scan | Karen mode |
|---|---|---|
| Ports | Chosen by the profile | All 65,535, unless you use `-p` |
| Service and version | Banner plus one safe probe | More probes for ports it can't identify |
| Web ports | Server header | Page title, headers and the app behind them |
| TLS ports | | Certificate details and problems |
| Operating system | | A guess, showing which port gave each clue |
| Misconfigurations | | Proved and marked `CONFIRMED` |

These checks do the smallest exchange that proves the problem, then leave. They never guess passwords or read data.

| Check | What it proves | How |
|---|---|---|
| `ftp-anonymous` | Anyone can log in to FTP | Logs in as the public `anonymous` user and quits |
| `open-shell` | A port hands out a command prompt | Recognises the prompt and never types into it |
| `redis-no-password` | Redis has no password | Reads the reply to the read-only `INFO server` |
| `mongodb-no-auth` | MongoDB has no login | Asks for databases matching a made-up name, so no real names come back |
| `telnet-open` | Telnet is running | Reads its greeting and doesn't log in |

## How it works

```
your targets  →  find open ports  →  ask each port what it is  →  match the answer to a product
              →  (Karen mode) web pages, certificates, OS guess, safe checks  →  report
```

1. **Port finder:** an async TCP connect scan with a worker pool. Ports that time out get a second, slower try, and it slows down by itself if the system runs out of sockets.
2. **Banner grabbing:** listens first, because many services speak first, then sends one harmless message. It tries TLS if plain text fails, and reads at most 4 KB.
3. **Fingerprints:** regex rules turn a banner into a product, version and CPE name. The CPE is what will link a service to its CVEs.

## How good is it?

Tested against a real Metasploitable 2:

- A default scan found 24 open ports, and nmap's default top 1000 ports found 23. The two tools use different port lists.
- A full Karen mode scan from Kali found 30 open ports.

nmap is still better at identifying services that wait for the client to speak in their own protocol. PostgreSQL, DNS (BIND), SMB (Samba), java-rmi and the UnrealIRCd version are named from the port number or left out for now.

Other limits:

- TCP only, so no UDP services yet.
- It makes full connections, which the target can log.
- The Redis and MongoDB checks have only been tested against local fake servers so far, not real ones.
- Versions are what a service says about itself, and Linux distributions often patch old versions without changing the number.

## Roadmap

- [x] **Part 1:** built-in scanner, Karen mode and safe checks
- [ ] Finish lab testing on Vulhub
- [ ] **Part 2:** collect data from NVD, CISA KEV, Exploit-DB and EPSS (`dingdongditch update-db`)
- [ ] **Part 3:** train a model on which CVEs really got exploited, and compare it with CVSS and EPSS
- [ ] **Part 4:** match services to CVEs and show a risk score per port, with why and how to fix it
- [ ] **Part 5:** demo GIF and PyPI release

Why a model? Knowing a service has CVEs is a database lookup. The hard part is prioritizing: an old OpenSSH can have dozens of CVEs, but only a few are ever exploited in the wild.

## Project layout

```
src/dingdongditch/
  cli.py           # the `dingdongditch` command
  targets.py       # IPs, hostnames, subnets → list of IPs
  ports.py         # port lists and profiles
  connect_scan.py  # finds open ports
  probes.py        # banner grabbing
  fingerprints.py  # banner → product, version, CPE
  http_info.py     # Karen mode: page title, headers, app
  tls_info.py      # Karen mode: certificates
  os_guess.py      # Karen mode: OS guess
  misconfig.py     # Karen mode: CONFIRMED checks
  mongo_wire.py    # just enough MongoDB protocol for its check
  own_scanner.py   # runs the steps above in order
  nmap_scanner.py  # the optional nmap engine
  nmap_parser.py   # nmap XML → services
  collect.py, features.py, train.py, matcher.py, scorer.py  # not built yet
man/               # the man page
tests/             # pytest, using fake local servers
```

## Development

```bash
git clone https://github.com/Mamdouhelzein/dingdongditch.git
cd dingdongditch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest -q
```

## Legal and ethical use

DingDongDitch detects problems and never exploits them. Only scan systems you own or have **explicit written permission** to test, because scanning without authorization is illegal in many countries. For practice, use lab VMs like Metasploitable 2 on a private network.

## License

MIT © Mamdouh El Zein
