# Changelog

What changed in each release of DingDongDitch, newest first.

## 0.1.0

The first release. It's alpha: it works on the lab machines it was tested on, and the output may still change.

### Scanning
- Built-in scanner, so nmap isn't needed: quick, default (about 1,100 ports) and full profiles, exact ports and ranges, several hosts and subnets.
- Slows itself down when the system runs out of sockets, and rechecks ports that timed out.
- Works out the service, product and version behind each open port from what it says, for about 25 common services.
- `--karen-mode`: every port, more questions per port, web page titles and headers, TLS certificates, an OS guess, and version questions for DNS, PostgreSQL, IRC and SMB.
- CONFIRMED checks that prove a problem without exploiting it: anonymous FTP, an open shell with no login, Redis with no password, MongoDB with no authentication, and Telnet.
- `--engine nmap` uses nmap instead, and `analyze` reads a saved nmap XML file.
- `--json` prints the results as JSON.

### Vulnerability data and the risk model
- `update-db` downloads NVD, CISA's list of exploited CVEs (KEV), EPSS and the Exploit-DB index into a local SQLite file, then retrains the risk model.
- `train` teaches a model which CVEs attackers really use. `train --test` checks it fairly by training only on what was known on a past day: from May 2025 and from May 2023 it found more of the CVEs CISA listed next than CVSS or EPSS did.
- Logistic regression by default; `train --xgboost` uses XGBoost, an optional extra.

### Risk per port
- Each service is matched to the CVEs NVD lists for its version, and each CVE gets a level: KNOWN EXPLOITED, HIGH, MEDIUM or LOW.
- The worst CVEs come with "riskier than N% of CVEs", why the model thinks so, and the first fixed release.
- A public remote exploit on Exploit-DB always makes a CVE at least HIGH, because the model ranks old CVEs too low.

### Known limits
- CVEs are matched on the version number alone, so a Linux distribution's patched package can still match.
- Tested on Metasploitable 2 so far. More lab tests (Vulhub) are still to come.
