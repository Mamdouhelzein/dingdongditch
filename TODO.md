# DingDongDitch – Part 1: our own scanner

Tick a box (`[x]`) when a step is done and committed.

## Core scanner
- [x] 1. Port lists and profiles (`ports.py`) + tests
- [x] 2. Port finder (`connect_scan.py`): async TCP connect scan, concurrency limit, timeouts
- [x] 3. Banner grabbing + probes (`probes.py`): listen first, then send safe probes, TLS on TLS ports
- [x] 4. Fingerprints (`fingerprints.py`): banner → product / version / CPE (~25 common services)
- [x] 5. CLI: `--engine own|nmap` (default `own`) and `--karen-mode` flag
- [x] 6. Tests with fake local servers (no network needed, works in CI)

## `--karen-mode` extras (Part 1b)
- [x] 7. Fast all-ports scan (65,535 ports, auto-lower speed if the system limit is hit)
- [x] 8. Multiple probes per port
- [x] 9. HTTP titles + headers
- [x] 10. TLS certificate info (subject, issuer, expiry)
- [x] 11. OS guess from banners (shown as a guess, with where it came from)

## Safe misconfiguration checks (show CONFIRMED)
- [x] 12. Anonymous FTP login allowed
- [x] 13. Redis with no password
- [x] 14. MongoDB with no auth
- [x] 15. Telnet open

## Wrap up Part 1
- [ ] 16. Test against Vulhub labs on Kali
- [x] 17. Update README (own scanner is default, nmap is backup) + man page
- [x] 18. Push to GitHub

## Part 6: evidence
- [x] 19. Possible matches: ranges with no first affected release never set a port's level
- [x] 20. `train --test`: 95% intervals, the model against EPSS CVE by CVE, the giveaway check, several years added up, `--tune`
- [x] 21. Answer key for the matcher (`data/lab_truth.json`) and `python -m dingdongditch.lab_check`
- [x] 22. README: what is and isn't shown, why not nmap; model card
- [ ] 23. Run `update-db --epss-date` for 1 May of 2022 to 2025, then `train --test` on those four days with `--tune`, and put the table in the README and model card
- [ ] 24. Scan Metasploitable 2 again and record a new demo GIF
- [ ] 25. Run `lab_check`, then add each Vulhub lab scanned in step 16 to the answer key
- [ ] 26. Try the Redis and MongoDB checks against real servers

## Later bonus
- [ ] SYN scan (needs root)
