# Security

HunterIntel fetches things on behalf of a user and stores what it learns, so it treats every indicator as untrusted input and every outbound request as a liability.

## Threat model

| Threat | Control | Where | Tested |
|---|---|---|---|
| **SSRF via the redirect probe** | Opt-in (`ALLOW_ACTIVE_PROBES`). http/https only; port allow-list (80/443/8080/8443); no `user:pass@`; every hop re-validated; destination resolved **once** and *every* address must be public; the TCP connection goes to that validated literal IP (SNI/cert still verified against the hostname); no cookies/credentials; bodies never read; hop and time limits. | `core/http.py` | real-socket tests incl. DNS-rebinding |
| **SSRF via provider calls** | Providers declare `allowed_hosts`; the gateway refuses other hosts and non-HTTPS; same connect-time guard; redirects off by default and re-validated (secret headers dropped on cross-host hops) when allowed (RDAP). | `core/http.py` | gateway tests |
| **IP-filter bypasses** | Classifier unwraps IPv4-mapped, 6to4, NAT64 and Teredo; blocks private, loopback, link-local (cloud metadata `169.254.169.254`), CGNAT, multicast, reserved, documentation; legacy numeric hosts (`2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`) are resolved to the real address first. | `core/netpolicy.py` | ~60 parametrised cases |
| **Leaking internal names/addresses to third parties** | Private/internal indicators are classified locally; every remote provider is `blocked` with the reason (even DNS). `do_not_share` and TLP:RED/AMBER+STRICT members are local-only. E-mail never leaves as-is. | `domain/indicators.py`, `services/enrichment.py` | enrichment + API tests assert no request is made |
| **Unintended sharing** | Query plan before any send; keyed vendors never pre-selected by default; active probe never pre-selected; hash lookups send the digest only. **No upload code path exists**; a test asserts no provider sends multipart/binary bodies and VirusTotal is `GET`-only. | `services/enrichment.py`, providers | cross-provider test |
| **Resource exhaustion** | Connect/read timeouts + total deadline; streamed reads aborted at the byte cap; non-identity `Content-Encoding` refused (decompression-bomb guard); bounded fan-out (certs, SAN domains, edges per run, graph nodes); JSON body ≤ 1 MB; upload cap with streaming (no disk spooling). | `core/http.py`, `api/app.py`, `services/filetype.py` | gateway + API tests |
| **Secret exposure** | Keys only from env, `SecretStr`, header-only, `redact()` on every error/message before storage or display, `/providers` returns `configured: bool` only, repr/dump of settings is clean. | `config.py`, `core/redact.py` | config, gateway, enrichment, API tests |
| **Outbound abuse / ToS** | Per-provider + global sliding-window rate limits (Redis-shared across workers), response cache, ToS links surfaced in the UI. | `core/ratelimit.py` | memory + Redis tests |
| **Unauthorised API use** | Optional bearer token (constant-time compare); per-IP inbound rate limit (tighter on `/enrich`); strict CORS allow-list; auth on every route but `/health`. | `api/deps.py` | API tests |
| **XSS / injection in stored or exported analyst text** | SQLAlchemy bound parameters only; reports rendered by auto-escaping Jinja2 and served as `attachment` with `Content-Security-Policy: default-src 'none'; sandbox`; the SPA never uses `dangerouslySetInnerHTML` and only links known vendor hosts; indicators containing control characters are rejected (header/log injection). | `services/reports.py`, frontend | API test with `<script>`, `<img onerror>`, `<svg onload>` payloads |
| **Active scanning / scraping** | None: no port scans, no crawling, no authenticated or private-resource access. The single active feature is the probe above. | – | – |
| **Personal data** | RDAP personal/registrant contact data is never read; entities flagged individual are skipped; no Gravatar-style lookups; e-mail local-parts never sent. | `providers/rdap.py` | RDAP test |

## Deployment checklist

1. **Set `HUNTERINTEL_API_TOKEN`** to a long random value whenever the API is reachable by anyone but you. The Compose file publishes only the web container, on loopback.
2. Terminate **TLS** in front (the bundled nginx speaks HTTP). Keep the backend port unpublished. If you run the API directly behind your own proxy, set uvicorn's `--forwarded-allow-ips` to that proxy only — per-IP rate limiting trusts `X-Forwarded-For` from allowed proxies.
3. Run migrations with `alembic upgrade head` and keep `HUNTERINTEL_AUTO_CREATE_SCHEMA=false`.
4. Give the container **egress to the public Internet only** (DNS resolvers, provider hosts). The in-process SSRF guard is defence in depth, not a substitute for network policy — block RFC 1918 / link-local / metadata egress at the firewall too.
5. Use a **Redis** instance when running more than one worker so the vendor quotas you configured are actually shared.
6. Treat the database as sensitive: it holds your investigations and analyst notes. Back it up and restrict access.
7. Review each provider's terms (see `PROVIDERS.md`) — in particular VirusTotal's non-commercial public-API restriction.
8. Keep `HUNTERINTEL_ALLOW_ACTIVE_PROBES=false` unless you are authorised to contact the targets you investigate.

## What is and isn't covered

* The guard defends against DNS rebinding for HTTP made through the gateway. DNS queries themselves go to the configured resolvers only and cannot be redirected by the queried name.
* A malicious *provider* response can at worst produce bogus data inside bounded structures: parsers cap sizes, tolerate missing/odd fields, and never evaluate content.
* There is **no multi-user model**: one deployment is one trust domain. Do not expose it to untrusted users; there is no per-user RBAC or audit trail beyond the stored provider-run log.
* Dependencies are not vendored; run `pip-audit` / `npm audit` in your pipeline.

## Reporting a vulnerability

Please open a private security advisory on the repository (or email the maintainers) rather than a public issue. Include the version, a reproduction, and the impact. Reports about SSRF-guard bypasses, secret exposure, or ways to make HunterIntel send an indicator to a provider you did not select are especially welcome.
