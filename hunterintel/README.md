# HunterIntel

**A modular OSINT & Cyber Threat Intelligence platform for SOC analysts, incident responders and researchers.**

HunterIntel aggregates public and optional third-party sources, turns raw intelligence into structured, *attributed* evidence, scores it in an explainable way, and lets analysts organise the result into investigations they can export as reports. It is built to be a practical investigation tool, not another domain-lookup page — and to be honest about what it does and does not know.

> **Name.** The original brief used both *HUNTERINTEL* and *MONKEINTEL*. The code uses **HunterIntel** (`hunterintel` package, `HUNTERINTEL_*` environment variables). The display name is a single constant per tier — `Settings.app_name` and `frontend/src/brand.ts` — if you prefer the other.

---

## What makes it different

| | |
|---|---|
| **Evidence you can trust** | Every datum is labelled **Verified** (observed first-hand from the source of record or computed locally), **Provider claim** (asserted by a third party, always attributed) or **Inferred** (derived by HunterIntel, with its basis). Information that could not be obtained is shown as an explicit **gap** (`not_configured`, `blocked`, `rate_limited`, `timeout`, `error`, `no_data`) — never silently dropped, never rendered as "clean". |
| **No fake data, no pretend APIs** | There is no bundled intelligence. If a source is unreachable the UI says so. *Unknown* is never *safe*. |
| **Nothing is sent without your say-so** | Searching parses locally (zero egress). A **query plan** then shows every provider that *would* receive the indicator and exactly what it would receive. Only providers you tick run. Keyed vendors are never pre-selected under the default policy. **No code path uploads files.** |
| **Works with zero API keys** | DNS, RDAP (via the IANA bootstrap), Team Cymru IP→ASN, certificate transparency and local analysis need no credentials. Keys switch on VirusTotal, AbuseIPDB, OTX, URLhaus and MalwareBazaar. |
| **Safe to run on a network you care about** | Private/loopback/link-local/internal indicators are never sent to remote providers. A connect-time SSRF guard pins validated IPs. Timeouts, size caps and rate limits everywhere. Secrets are `SecretStr`s that never reach logs, errors or API responses. |
| **Extensible** | A provider is one class. Adding a source never touches the orchestrator, scoring, database or UI. |

## Features

* **Indicators:** domains, IPv4/IPv6, URLs, MD5/SHA-1/SHA-256, SSL certificates, ASNs and e-mail addresses (only the domain part is ever looked up). Defanged input (`hxxps://evil[.]com`) is restored; IDN/punycode, obfuscated IP hosts (`2130706433`, `0x7f.1`) and URL canonicalisation are handled.
* **Domain intelligence:** A/AAAA/MX/NS/TXT/CNAME/SOA/CAA, SPF & DMARC posture, RDAP registration/expiry/registrar/status/nameservers (personal contact data is deliberately dropped), certificate transparency with honest truncation/overload reporting.
* **IP intelligence:** reverse DNS with **forward confirmation**, RDAP network ownership, origin ASN/prefix/AS name, optional local GeoIP database — with the accuracy limitations attached to every result.
* **URL intelligence:** normalisation, component analysis, structural heuristics (userinfo trick, IDN homographs, executable payloads, …), reputation integrations, and an **opt-in, SSRF-guarded redirect-chain probe** (headers only, bodies never read).
* **Hash intelligence:** MD5/SHA-1/SHA-256 recognition, VirusTotal / MalwareBazaar / URLhaus / OTX lookups (identifier only), and a **local file tool** that hashes and type-identifies a file on your own server and discards it.
* **Relationship graph:** domains ⇄ IPs ⇄ certificates ⇄ ASNs ⇄ hashes ⇄ URLs, with edge style encoding assurance (solid = verified, dashed = provider claim, dotted = inferred) and read-time **inferred** shared-infrastructure links (graded weak/medium, with caveats).
* **Threat-intelligence store:** IOC storage, enrichment history (changes are new versions, unchanged facts just extend `last confirmed`), confidence & risk scoring with a full breakdown, source attribution, first/last seen, TTL-based freshness and expiry, tags and analyst classification.
* **Investigation workspace:** investigations with TLP, findings that **snapshot their evidence**, analyst notes, indicator comparison, and Markdown / JSON / self-contained HTML report export (defanged by default).
* **Professional dark UI:** global search (Ctrl K), query plan, IOC details, provider results, risk indicators, history timeline, graph, export.

## Quick start

### Docker Compose (API + web + PostgreSQL + Redis)

```bash
cd hunterintel
cp .env.example .env        # set POSTGRES_PASSWORD; add API keys / HUNTERINTEL_API_TOKEN if you want them
docker compose up --build
```

Open <http://127.0.0.1:8080>. Only the web container is published, and only on loopback. Put a TLS-terminating reverse proxy in front of it and set `HUNTERINTEL_API_TOKEN` before exposing it to anyone else.

### Local development

```bash
# backend (Python 3.12+)
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
uvicorn hunterintel.api.app:app_factory --factory --reload      # http://localhost:8000/docs

# frontend (Node 20+), in another terminal
cd frontend
npm install
npm run dev                                                      # http://localhost:5173 (proxies /api)
```

SQLite is used by default (`hunterintel.db`, created on start). Set `HUNTERINTEL_DATABASE_URL=postgresql+asyncpg://…` for PostgreSQL and run `alembic upgrade head` (see *Database*).

### Try a sample investigation

```bash
python scripts/load_sample.py samples/01-getting-started.json            # creates it; sends nothing anywhere
python scripts/load_sample.py samples/01-getting-started.json --enrich    # runs the keyless public sources
python scripts/load_sample.py samples/03-policy-demo-private-indicators.json --enrich   # shows the safety controls
```

Samples contain **seed indicators only** (reserved example names, a public resolver, the EICAR test-file hashes, and private/internal indicators for the policy demo). All evidence is fetched live when you enrich. Third-party providers additionally require `--yes`.

## Configuration

Everything is optional. See [`.env.example`](.env.example) for the full annotated list.

| Variable | Purpose | Default |
|---|---|---|
| `HUNTERINTEL_DATABASE_URL` | SQLAlchemy URL (`sqlite+aiosqlite://…` or `postgresql+asyncpg://…`) | SQLite file |
| `HUNTERINTEL_REDIS_URL` | Shared rate limiting + response cache across workers | in-memory |
| `HUNTERINTEL_API_TOKEN` | Require `Authorization: Bearer <token>` on `/api/v1` | off (local use) |
| `HUNTERINTEL_DEFAULT_SHARING` | Highest tier pre-selected in a plan: `local` \| `public` \| `third_party` | `public` |
| `HUNTERINTEL_ALLOW_ACTIVE_PROBES` | Enable the opt-in redirect-chain probe | `false` |
| `HUNTERINTEL_DNS_RESOLVERS` | Resolvers used for DNS and Team Cymru lookups | `1.1.1.1,9.9.9.9` |
| `HUNTERINTEL_PROVIDER_RATE_LIMITS` | Overrides, e.g. `virustotal=4/60,crtsh=1/3` | vendor-guided defaults |
| `HUNTERINTEL_GEOIP_DB_PATH` | A MaxMind-format `.mmdb` you are licensed to use | unset |
| `VIRUSTOTAL_API_KEY` · `ABUSEIPDB_API_KEY` · `OTX_API_KEY` · `ABUSECH_AUTH_KEY` | Provider credentials (env only) | unset |

API keys live only in environment variables, are held as `SecretStr`, travel only in request *headers*, are redacted from every error string, and are never returned by any endpoint (`/providers` reports `configured: true/false` only).

## Providers

| Provider | Key | Tier | Handles | Evidence label |
|---|---|---|---|---|
| `local` | – | local | everything | verified (facts) / inferred (heuristics) |
| `dns` | – | public | domain, IP, e-mail (domain part) | verified |
| `rdap` | – | public | domain, IP, ASN | verified |
| `cymru` | – | public | IP, ASN | provider claim |
| `crtsh` | – | public | domain, certificate | provider claim |
| `geoip_local` | your `.mmdb` | local | IP | provider claim (with accuracy caveat) |
| `probe` | opt-in | **active** | URL | verified |
| `virustotal` | `VIRUSTOTAL_API_KEY` | third party | domain, IP, URL, hash | provider claim |
| `abuseipdb` | `ABUSEIPDB_API_KEY` | third party | IP | provider claim |
| `otx` | `OTX_API_KEY` | third party | domain, IP, URL, hash | provider claim |
| `urlhaus` | `ABUSECH_AUTH_KEY` | third party | URL, domain, IP, MD5/SHA-256 | provider claim |
| `malwarebazaar` | `ABUSECH_AUTH_KEY` | third party | hash | provider claim |

Details, endpoints used, what each receives, rate limits and ToS notes: [`docs/PROVIDERS.md`](docs/PROVIDERS.md).

## How scoring works (and why it is not a black box)

Reputation providers emit normalised *signals* `{verdict, strength, reliability}`.

* **Risk** `= 100 · (1 − Π(1 − strength·reliability·freshness))` over malicious-leaning signals (noisy-OR), then combined with a *capped* contribution from structural heuristics, which can never reach "suspicious" on their own.
* **Confidence** `= 100 · (1 − Π(1 − reliability·freshness))` over independent sources that **agree** with the verdict (×0.7 if sources conflict). A source that has no record contributes nothing.
* **Verdict:** `malicious ≥ 70 · suspicious ≥ 40 · low risk > 0 · no detections` (a definitive clean signal, zero risk) `· unknown` (no determination, or expired).
* **Freshness:** TTLs by type (IP/URL 30 d, domain 90 d, e-mail 180 d, hash/cert/ASN 365 d). Evidence decays after 25% of the TTL and an expired indicator is not assessed.

Every score is returned with a breakdown of each contribution; the UI shows it. Analyst classification (`benign`, `suspicious`, `malicious`, `false positive`) is stored *separately* from the computed verdict.

## Security model (summary)

SSRF prevention (connect-time IP pinning, per-hop redirect validation, port/scheme allow-lists), private-range lookup blocking, request timeouts and response-size caps (including a decompression-bomb guard), per-provider and global outbound rate limits (Redis-backed when available), optional bearer-token auth with constant-time comparison, inbound rate limiting and body-size limits, strict CORS, secret redaction, auto-escaped HTML reports with a locked-down CSP, and no active scanning. Full threat model and deployment checklist: [`docs/SECURITY.md`](docs/SECURITY.md).

## API

Interactive docs at **`/docs`** (Swagger UI) and `/redoc` on the running backend; the schema is committed at [`docs/openapi.json`](docs/openapi.json) and summarised with `curl` examples in [`docs/API.md`](docs/API.md).

## Database

```bash
cd backend
alembic upgrade head          # uses HUNTERINTEL_DATABASE_URL
alembic revision --autogenerate -m "change"   # after editing db/models.py
```

Set `HUNTERINTEL_AUTO_CREATE_SCHEMA=false` in production (the Compose file does) so Alembic owns the schema. The migration is tested to match the ORM metadata exactly, up and down, on SQLite and PostgreSQL.

## Testing

```bash
cd backend
pytest                                                    # ~320 tests, no network needed
HUNTERINTEL_TEST_REDIS_URL=redis://localhost:6379/0 pytest                 # + Redis rate limiter / cache
HUNTERINTEL_TEST_DATABASE_URL=postgresql+asyncpg://u:p@localhost/db pytest # the DB-backed suite on PostgreSQL
ruff check hunterintel tests alembic

cd ../frontend
npm run typecheck && npm test && npm run build
```

What the suite covers: IP/hostname policy (incl. IPv4-mapped, 6to4, NAT64 and obfuscated forms), the SSRF guard **over real sockets** including a DNS-rebinding scenario, gateway limits and redirect handling, indicator parsing, every provider's parsing and failure modes against documented payload shapes, scoring, history/dedup, privacy-policy enforcement, report escaping, and the whole API over ASGI.

## Verification status

Read this before relying on the results.

* **Verified here:** the full backend suite (SQLite; PostgreSQL 16 and Redis 7 via the env vars above), the SSRF guard against real loopback sockets, the Alembic migration up/down on both databases, a non-editable install + `alembic upgrade head` + `uvicorn` on PostgreSQL (replaying the backend Dockerfile steps), the real server end-to-end through its production HTTP/DNS code paths, the frontend type-check/unit tests/production build, and every page rendered in a real browser against a seeded backend with zero console errors.
* **Not verified against live services:** the provider adapters (RDAP, crt.sh, Team Cymru, VirusTotal, AbuseIPDB, OTX, URLhaus, MalwareBazaar). The development sandbox blocked all outbound intelligence hosts and intercepted DNS, so these were built from the vendors' documented request/response formats and tested with *schema-shaped fixtures* (clearly marked as test inputs, not intelligence). Expect to fix small field-level mismatches on first live use — a schema surprise is reported as an `error` run with a clear message, never as an empty/clean result. In particular, abuse.ch's `Auth-Key` requirement was confirmed only from secondary sources.
* **Not run:** `docker build` / `docker compose up` (no Docker daemon in the sandbox). The Compose file passes `docker compose config`, and the backend image's install/migrate/serve sequence was replayed manually.
* **Environment artefact:** in the sandbox every DNS name returned NXDOMAIN; HunterIntel faithfully reported that as "per the configured resolvers". Make sure your configured resolvers are reachable.

## Project layout

```
backend/hunterintel/
  config.py            typed settings (SecretStr, safe defaults)
  core/                netpolicy · http (gateway + SSRF guard) · ratelimit · cache · redact
  domain/              indicators (parse/normalise) · evidence model · URL analysis
  db/                  SQLAlchemy 2.0 async models · session
  providers/           base (adapter ABC) · one module per source · registry
  services/            enrichment · store · scoring · graph · compare · investigations · reports · filetype
  api/                 FastAPI app · deps (auth, rate limits) · routers
backend/alembic/       migrations         backend/tests/   ~320 tests
frontend/src/          React + TypeScript + Tailwind SPA (api · components · pages · lib)
samples/               seed investigations   scripts/load_sample.py
docs/                  ARCHITECTURE · API · PROVIDERS · SECURITY · openapi.json
```

Adding a provider: subclass `Provider`, declare `name / tier / supported_types / allowed_hosts`, implement `lookup()`, add it to `providers/registry.py`. See [`docs/PROVIDERS.md`](docs/PROVIDERS.md#writing-a-provider).

## Limitations & roadmap

* Passive-DNS and WHOIS history are paid datasets; HunterIntel builds its own history from your enrichments rather than pretending to have one.
* RDAP coverage varies by TLD; crt.sh is best-effort and often overloaded for large domains (reported, not hidden).
* Not implemented (ideas): STIX 2.1 export, TAXII feeds, scheduled re-enrichment, multi-user accounts/RBAC, HIBP-style breach lookups (paid/ToS-restricted), per-file YARA scanning.

## Responsible use

HunterIntel performs no port scans, crawling, authenticated access or scraping of private resources. The only action that touches a target is the opt-in redirect probe — one bounded request per hop, public addresses only. Respect each provider's terms of service (see `docs/PROVIDERS.md`) and the privacy of the people behind indicators.

## License

MIT — see [`LICENSE`](LICENSE).
