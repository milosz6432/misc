# HunterIntel API

Base path `/api/v1`. Interactive documentation is served by the running backend at `/docs` (Swagger UI) and `/redoc`; the machine-readable schema is committed as [`openapi.json`](openapi.json) (regenerate with `python scripts/export_openapi.py` from `backend/`).

## Conventions

* **Auth.** If `HUNTERINTEL_API_TOKEN` is set, send `Authorization: Bearer <token>` on every call except `GET /health`. Without it the API is open (intended for local use).
* **Errors.** `{"detail": {"code": "<stable_code>", "message": "<human text>"}}`. Codes: `invalid_indicator`, `invalid_request`, `not_found`, `unauthorized`, `rate_limited` (with `Retry-After`), `too_large`, `internal_error` (never contains internals). Schema validation failures use FastAPI's standard 422 shape.
* **Limits.** JSON bodies ≤ 1 MB (the file tool has its own limit, default 25 MiB). Inbound rate limit per client IP (`HUNTERINTEL_INBOUND_RATE_LIMIT_PER_MINUTE`, default 240); `/enrich` gets one-eighth of that (min 5/min) because it spends third-party quota.
* **Evidence labels.** Every observation/edge carries `assurance` ∈ `verified | provider_claim | inferred`. Provider outcomes use `status` ∈ `ok | no_data | not_configured | blocked | rate_limited | timeout | error`.
* **Verdicts.** `malicious | suspicious | low_risk | no_detections | unknown`. `unknown` means no determination — never "safe".
* **Extra fields** in request bodies are rejected (422).

```bash
export HI=http://127.0.0.1:8000/api/v1
export AUTH='Authorization: Bearer '$HUNTERINTEL_API_TOKEN   # omit if auth is off
```

## The privacy-preserving flow

```bash
# 1. Parse + plan. ZERO network egress. Shows what each provider would receive.
curl -s -X POST $HI/indicators/classify -H "$AUTH" -H 'content-type: application/json' \
  -d '{"value":"hxxps://Evil[.]example[.]com/login"}'
# → { "indicator": {"type":"url","value":"https://evil.example.com/login","remote_lookup_allowed":true,…},
#     "known": null,
#     "plan": [ {"provider":"local","state":"available","selected_by_default":true,"data_shared":"Nothing — …"},
#               {"provider":"virustotal","state":"not_configured","reason":"No VirusTotal API key. …"}, … ] }

# 2. Run only what you choose. Omit "providers" for the default plan (local + keyless public sources).
curl -s -X POST $HI/enrich -H "$AUTH" -H 'content-type: application/json' \
  -d '{"value":"example.com","providers":["dns","rdap","crtsh"]}'
```

`/enrich` returns the full indicator detail plus `runs` (one per provider with status/message/duration), `new_observations` and `relationships_stored`. Requesting a provider that is unavailable, blocked by policy or unconfigured **does not error** — it is recorded as a run with the reason, and nothing is sent.

## Endpoints

### System

| Method & path | Purpose |
|---|---|
| `GET /health` | Liveness + non-sensitive config (`auth_required`, `redis`, `active_probes_enabled`, `default_sharing`). No auth. |
| `GET /providers` | Every provider: tier, supported types, `configured`, `key_env`, rate limit, terms URL. **Never any key material.** |
| `GET /stats` | Dashboard counts, recent indicators, recent provider failures, recent investigations. |

### Indicators

| Method & path | Purpose |
|---|---|
| `POST /indicators/classify` `{value, type?}` | Normalise, classify, return lookup policy and the query plan. Local only. |
| `POST /enrich` `{value, type?, providers?, refresh?}` | Run selected providers, persist evidence, score. |
| `GET /indicators` | Browse the IOC store. Filters: `q` (substring), `type`, `verdict`, `classification`, `tag`, `tracked` (default true), `include_expired` (default false); `sort` ∈ `last_seen first_seen risk confidence value`, `desc`, `limit` ≤ 200, `offset`. |
| `GET /indicators/{id}` | Detail: fresh assessment with score breakdown, latest observation per provider/kind, last run per provider, plan, tags with sources, investigations. |
| `GET /indicators/{id}/observations` | Full history. `provider`, `kind`, `limit`. |
| `GET /indicators/{id}/runs` | Provider run log including failures. |
| `GET /indicators/{id}/graph` | `depth` 1–4 (default 2), `inferred` (default true). Nodes + edges (merged by relation, with per-source evidence). |
| `PATCH /indicators/{id}` | `classification`, `do_not_share`, `tracked`, `ttl_days`, `add_tags`, `remove_tags`. |
| `DELETE /indicators/{id}` | Delete with evidence; findings keep their snapshots. |
| `POST /compare` `{indicator_ids: [2..10]}` | Shared infrastructure/tags/attributes, graded `weak|medium|strong`, always `inferred`. |

### Investigations

| Method & path | Purpose |
|---|---|
| `POST /investigations` `{title, description?, tlp?}` · `GET /investigations` | Create / list. `tlp` ∈ `clear green amber amber_strict red`. |
| `GET|PATCH|DELETE /investigations/{id}` | Detail (with indicators, findings, notes) / update / delete (indicators are kept). Raising TLP to `red`/`amber_strict` immediately marks all members do-not-share. |
| `POST /investigations/{id}/indicators` `{value[,type]}` or `{indicator_id}` | Add (idempotent). Triggers **no** enrichment. |
| `DELETE /investigations/{id}/indicators/{indicator_id}` | Remove. |
| `POST /investigations/{id}/notes` · `PATCH|DELETE …/notes/{note_id}` | Analyst notes (optionally attached to a member indicator). |
| `POST /investigations/{id}/findings` · `PATCH|DELETE …/findings/{finding_id}` | Findings. Pass `observation_id` to **snapshot** that observation as evidence; the snapshot survives later re-enrichment. |
| `GET /investigations/{id}/graph` | Graph of all member indicators; `depth` 0–3. |
| `GET /investigations/{id}/export?format=md\|json\|html&defang=true` | Report download (`Content-Disposition: attachment`, locked-down CSP). Markdown/HTML defang indicators by default; JSON always keeps raw values. |

### Tools

| Method & path | Purpose |
|---|---|
| `POST /tools/file-hash` | Body = the raw file bytes (`application/octet-stream`; optional `X-Filename`). Returns `md5`, `sha1`, `sha256`, `size` and a magic-byte `file_type`. The bytes are streamed through hashlib and discarded: never stored, never forwarded. |

```bash
curl -s -X POST $HI/tools/file-hash -H "$AUTH" -H 'X-Filename: sample.bin' --data-binary @sample.bin
```

## Example: investigate, annotate, export

```bash
ID=$(curl -s -X POST $HI/investigations -H "$AUTH" -H 'content-type: application/json' \
      -d '{"title":"Invoice phishing","tlp":"amber"}' | jq .id)

IND=$(curl -s -X POST $HI/enrich -H "$AUTH" -H 'content-type: application/json' \
      -d '{"value":"example.com"}' | jq .indicator.id)

curl -s -X POST $HI/investigations/$ID/indicators -H "$AUTH" -H 'content-type: application/json' -d "{\"indicator_id\":$IND}"
curl -s -X POST $HI/investigations/$ID/notes      -H "$AUTH" -H 'content-type: application/json' -d '{"body":"Check registrar abuse contact."}'
curl -s "$HI/investigations/$ID/export?format=md" -H "$AUTH" -o report.md
```
