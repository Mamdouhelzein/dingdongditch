# portrisk

> ML-powered risk scoring for open ports. Feed it an `nmap -sV` scan; it tells you which services are most likely to get you hacked, why, and how to fix them.

![status](https://img.shields.io/badge/status-early%20development-orange)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

## Why

Knowing a service has CVEs is easy: it's a database lookup. The hard part is **prioritizing**. An old OpenSSH can have dozens of CVEs, but only a few will ever be exploited in the wild.

`portrisk` trains a model on historical CVE data, labeled by whether each CVE was actually exploited (CISA KEV, Exploit-DB), to predict **exploit likelihood**, then rolls those predictions up into a risk score for every open port.

```
nmap -sV  →  services + versions  →  matching CVEs  →  ML exploit-likelihood per CVE
          →  risk score per port   →  explanation + hardening advice
```

## Quick start

```bash
git clone https://github.com/Mamdouhelzein/portrisk.git
cd portrisk
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

nmap -sV -oX scan.xml 192.168.56.101      # scan a machine you own / a lab VM
portrisk scan scan.xml
portrisk scan scan.xml --json
nmap -sV -oX - 192.168.56.101 | portrisk scan -
```

## Roadmap

- [x] Project setup, CLI skeleton, CI
- [x] Parse nmap XML (ports, products, versions, CPEs)
- [ ] **Phase 1:** collect data: NVD CVEs, CISA KEV, Exploit-DB, EPSS (`portrisk update-db`)
- [ ] **Phase 2–3:** labels + feature engineering (CVSS vector, CWE, description text)
- [ ] **Phase 4:** train & evaluate (time-based split, PR-AUC, vs. CVSS-only baseline and EPSS)
- [ ] **Phase 6:** match services to CVEs (CPE + version ranges, fuzzy fallback)
- [ ] **Phase 7:** per-port risk score + exposure rules (telnet, SMB, RDP, DBs...)
- [ ] **Phase 8:** explanations (SHAP) and hardening advice
- [ ] Publish to PyPI (`pip install portrisk`)

## Project layout

```
src/portrisk/
  cli.py          # `portrisk` command
  nmap_parser.py  # nmap XML → services
  collect.py      # download CVE / exploit data
  features.py     # CVE → features
  train.py        # train + evaluate model
  matcher.py      # service → CVEs
  scorer.py       # per-port risk score
tests/            # pytest, with a sample scan in tests/fixtures/
data/             # raw + processed datasets (gitignored)
models/           # trained models (gitignored)
notebooks/        # exploration
```

## Development

```bash
ruff check .   # lint
pytest -q      # tests
```

## ⚠️ Legal & ethical use

Only scan systems you own or have **explicit written permission** to test. Scanning networks without authorization is illegal in many countries. For practice, use lab VMs like Metasploitable 2 on a host-only network.

Risk scores are guidance, not proof: version detection can be wrong, and distros often backport patches without changing the version number.

## License

MIT © Mamdouh El Zein
