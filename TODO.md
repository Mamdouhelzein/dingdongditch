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
- [ ] 10. TLS certificate info (subject, issuer, expiry)
- [ ] 11. OS guess from banners (shown as a guess, with where it came from)

## Safe misconfiguration checks (show CONFIRMED)
- [ ] 12. Anonymous FTP login allowed
- [ ] 13. Redis with no password
- [ ] 14. MongoDB with no auth
- [ ] 15. Telnet open

## Wrap up Part 1
- [ ] 16. Test against Vulhub labs on Kali
- [ ] 17. Update README (own scanner is default, nmap is backup)
- [ ] 18. Push to GitHub

## Later bonus
- [ ] SYN scan (needs root)
