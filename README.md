# Save Me

**A free, installable web app that helps anyone set up DNS filtering at home and triage suspicious domains — no technical knowledge required.**

Live: https://wardcraftsec.github.io/Save-Me/

---

## What It Does

1. **Guided NextDNS setup** — 5 tabs, 16 steps, plain-English instructions for setting up DNS-over-TLS filtering on your router, phone, or any device. Takes about 5 minutes.
2. **IOC Site Checker** — paste any domain or IP, get instant results from 3 databases (AbuseIPDB, VirusTotal, ipinfo) with plain-English explanations of what each result means.
3. **MITRE ATT&CK mapped** — checker results are contextualised against known attack techniques.

## Tech Stack

| Layer | What |
|-------|------|
| Frontend | Vanilla HTML/CSS/JS. No frameworks. No build step. |
| Backend | Cloudflare Worker (4 endpoints: resolve, abuseipdb, vt, ipinfo) |
| Hosting | GitHub Pages (free tier) |
| Analytics | GoatCounter (privacy-respecting, no cookies) |
| APIs | AbuseIPDB, VirusTotal, ipinfo, Cloudflare DoH |

## Architecture

   User Browser
    │
    │  domain / IP
    ▼
Cloudflare Worker (save-me-proxy)
    │
    ├──→ Cloudflare DoH (resolve domain → IP)
    ├──→ AbuseIPDB API (abuse score, usage type)
    ├──→ VirusTotal API (malicious/suspicious/clean counts)
    └──→ ipinfo API (geo, org, ASN)
    │
    │  JSON
    ▼
User Browser → Plain-English Summary 

## How to Use

1. Open the [live site](https://wardcraftsec.github.io/Save-Me/)
2. Follow the 5 tabs in order (or jump straight to **Site Checker** if already set up)
3. For the checker: paste a domain or IP → hit Check → read the plain-English summary
4. Install as a PWA: browser menu → "Add to Home Screen"

## MITRE ATT&CK Mapping

| Checker Output | Technique | ID |
|---------------|-----------|-----|
| High VT malicious score + DNS domain | Command and Control over DNS | T1071.004 |
| High AbuseIPDB score + residential IP | Resource Hijacking (botnet C2) | T1496 |
| Domain resolving to unexpected ASN | Exfiltration Over Alternative Protocol | T1048 |
| New domain + high query volume | Application Layer Protocol: DNS | T1071.004 |

## Built On

Developed entirely on a **Pixel 7 running GrapheneOS**, using **Termux** and a web-based editor. No computer. No IDE. No build tools.

Started Oct 2026. Zero prior tech background.

## License

MIT. Use it, fork it, break it. See [LICENSE](LICENSE).   
