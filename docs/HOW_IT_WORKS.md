# How DingDongDitch works

```
your targets  →  find open ports  →  ask each port what it is  →  match the answer to a product
              →  (Karen mode) web pages, certificates, OS guess, safe checks
              →  look up its CVEs  →  score and explain each one  →  report
```

1. **Port finder:** an async TCP connect scan with a worker pool. Ports that time out get a second, slower try, and it slows down by itself if the system runs out of sockets.
2. **Banner grabbing:** listens first, because many services speak first, then sends one harmless message. Ports that say nothing are asked once more a moment later, because a small machine can still be busy with the port scan. It tries TLS if plain text fails, and reads at most 4 KB. Services that only answer in their own protocol get one read-only question in it: DNS servers are asked their `version.bind`, and PostgreSQL gets a startup message for a protocol version that doesn't exist. It refuses before any login, and its error message shows which releases it could be.
3. **Fingerprints:** regex rules turn a banner into a product, version and CPE name.
4. **CVE matching:** the CPE's product and version are compared with NVD's affected versions and ranges. A patch like OpenSSH's `4.7p1` counts as `4.7`, and products NVD files under more than one vendor name (vsftpd, MySQL, ProFTPD, UnrealIRCd) are looked up under all of them. A CVE that only matches a range with no first affected release ("before 4.10.18") is kept apart as a possible match.
5. **Scoring:** the model scores each CVE, and its biggest clues become the Why line.

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
  binary_probes.py # DNS and PostgreSQL questions, and reading their answers
  conversations.py # Karen mode: IRC and SMB hellos that reveal versions
  mongo_wire.py    # just enough MongoDB protocol for its check
  own_scanner.py   # runs the steps above in order
  nmap_scanner.py  # the optional nmap engine
  nmap_parser.py   # nmap XML → services
  db.py            # the local vulnerability database (SQLite)
  collect.py       # downloads CISA KEV, EPSS and the Exploit-DB index
  nvd.py           # downloads NVD's CVE feeds, one CVE at a time
  features.py      # CVEs as they were on a date → numbers for the model
  train.py         # trains, saves and time-travel-tests the model
  evaluate.py      # top 1% / 5% / 10% and the CVSS and EPSS baselines
  versions.py      # compares version numbers the way NVD writes them
  matcher.py       # a scanned service → the CVEs NVD lists for it
  scorer.py        # levels, "riskier than", why and fix for each CVE
  lab_check.py     # checks the matcher against data/lab_truth.json
  data/            # PostgreSQL error line -> release table
data/              # lab_truth.json: lab services and the CVEs known to affect them
docs/              # the demo GIF, the model card and this page
man/               # the man page
scripts/           # rebuilds the PostgreSQL table from its source
tests/             # pytest, using fake local servers
```
