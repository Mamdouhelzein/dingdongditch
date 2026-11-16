# Changelog

What changed in each release of DingDongDitch, newest first.

## Unreleased

### Matching
- A CVE that only matches a range with no first affected release ("every version before 4.10.18") is now a possible match, shown apart from the sure ones. A port's level comes from its sure CVEs only. This is what made Samba 3.0.20 `KNOWN EXPLOITED` through Zerologon (CVE-2020-1472) in 0.1.0.
- The Risk column shows the sure CVEs' worst level and count, then how many possible ones there are and their worst level. Below the table, each port's worst possible CVE is listed after its sure ones.
- `--json`: each CVE has `open_ended`, and `risk` has `possible_level` next to `level`. `level` no longer counts possible matches.
- `python -m dingdongditch.lab_check data/lab_truth.json` checks the matcher against an answer key of lab services and the CVEs known to affect them: how many it calls sure, calls possible or misses.

### Testing the model
- `train --test` prints a 95% interval for every number, from 2,000 bootstrap redraws of the listed CVEs.
- It compares the model with EPSS on the same listed CVEs: the gap with its interval, the CVEs only one of them caught, and a sign test.
- It repeats the test without every CVE whose description says it was exploited, since NVD may have added that after the attack.
- `--test` can be given more than once. Days a year or more apart are also added up into one table.
- `train --test ... --tune` chooses the settings for each test day on the year before it, so the choice of model is part of the test and not made after it.

### Docs
- The README says what the results do and don't show, and answers "why not just use nmap?".
- New: a model card (`docs/MODEL.md`) and how the pieces fit together (`docs/HOW_IT_WORKS.md`).
- Removed the empty `notebooks/`, `models/` and `data/` placeholder folders.

### Still to do
- The four-year test with intervals, a new demo capture, and lab tests on Vulhub.

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
