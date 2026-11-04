# Providers

A provider is an adapter that turns one source into normalised **observations**, **relationships**, **tags** and (for reputation sources) a **signal**. This page documents what each one sends, what it reads, its limits, and how it was verified.

> **Verification status.** None of the adapters below could be exercised against its live service during development: the build sandbox blocked all outbound intelligence hosts and intercepted DNS. Each was implemented from the vendor's documented request/response format and is covered by tests that use *schema-shaped fixtures* (marked as test inputs, not intelligence). A response that does not match the expected shape yields an `error` provider run with a clear message — never an empty or "clean" result. Vendor limits and terms change; **check the linked terms before use**.

## Privacy tiers

| Tier | Meaning | Pre-selected? |
|---|---|---|
| `local` | Nothing leaves this host. | yes |
| `public` | Keyless public infrastructure (DNS, RDAP, CT). The indicator is visible to that operator. | yes, if `HUNTERINTEL_DEFAULT_SHARING` ≥ `public` (default) |
| `third_party` | Keyed vendor. The indicator is sent to them. | **no**, unless `HUNTERINTEL_DEFAULT_SHARING=third_party` |
| `active` | HunterIntel itself contacts the target. Needs `HUNTERINTEL_ALLOW_ACTIVE_PROBES=true`. | **never** |

Independently of tiers: private/loopback/link-local/CGNAT/reserved/internal indicators, `do_not_share` indicators and members of TLP:RED / AMBER+STRICT investigations are **local-only** (every other provider is `blocked`, enforced server-side even for direct API calls). E-mail addresses are never sent as-is — only the domain part is queried, and no third-party provider accepts e-mail.

## Reference

| Provider | Sends | Reads | Default rate | Terms |
|---|---|---|---|---|
| **local** | nothing | parsing, structure, URL heuristics, hash recognition, EICAR match | – | – |
| **dns** | DNS queries to `HUNTERINTEL_DNS_RESOLVERS` | A, AAAA, NS, MX, TXT, CNAME, SOA, CAA; `_dmarc` TXT; PTR + forward confirmation | 100 q/s (internal cap) | your resolver's |
| **rdap** | the registrable domain / IP / AS number to the **authoritative** RDAP server, found via IANA's bootstrap (`data.iana.org/rdap/{dns,ipv4,ipv6,asn}.json`) | events (registration/expiry/changed), status, registrar name + IANA id + abuse e-mail, nameservers, DNSSEC; network name/handle/CIDR/country/owner **organisations**; AS name/country. **Entities flagged individual and registrant contact data are never read.** | 10 / 10 s | [IANA RDAP ToS](https://www.iana.org/help/rdap-terms-of-service) |
| **cymru** | a DNS query under `origin.asn.cymru.com` / `origin6.asn.cymru.com` / `asn.cymru.com` | origin ASN(s), prefix, RIR country, allocation date, AS name | via DNS cap | [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) — be gentle, no bulk use |
| **crtsh** | `https://crt.sh/?q=%.<domain>&output=json` (or a fingerprint / `crtsh:<id>`) | certificate id, serial, issuer, validity, SAN names; de-duplicated pre-cert/final pairs; capped (`HUNTERINTEL_MAX_CERTIFICATES`, `…_MAX_DISCOVERED_DOMAINS`) | 1 / 3 s | volunteer-run service; large domains can exceed the 8 MB cap or time out — reported as errors |
| **geoip_local** | nothing | a `.mmdb` you provide (country/city/lat-long/accuracy radius) | – | **your database's licence** |
| **probe** | HEAD (GET `Range: 0-0` if HEAD is refused) to the URL and each redirect target | status, `Location`, `Server`, `Content-Type`, remote IP; **bodies are never read** | 10 / 10 s | you are contacting the target — only use where permitted |
| **virustotal** | `GET /api/v3/{domains,ip_addresses,urls,files}/…` — identifier only, header `x-apikey` | last analysis stats, reputation, tags, categories, file metadata/threat labels, last DNS records, ASN | 4 / min | [VirusTotal ToS](https://docs.virustotal.com/docs/terms-of-service) (public API: non-commercial; mind daily quota) |
| **abuseipdb** | `GET /api/v2/check?ipAddress=…&maxAgeInDays=90`, header `Key` | confidence score, report counts, usage type, ISP, Tor flag, whitelist flag | 1000 / day | [AbuseIPDB terms](https://www.abuseipdb.com/terms) |
| **otx** | `GET /api/v1/indicators/{type}/{value}/general`, header `X-OTX-API-KEY` | pulse count/summaries, tags, adversaries, malware families, ATT&CK ids | 10 / min | [OTX terms](https://otx.alienvault.com/terms) |
| **urlhaus** | `POST /v1/{url,host,payload}/` form body, header `Auth-Key` | listing status, threat, tags, payloads, blacklists, URL list per host | 30 / min | [abuse.ch URLhaus API](https://urlhaus.abuse.ch/api/) |
| **malwarebazaar** | `POST /api/v1/` `query=get_info&hash=…`, header `Auth-Key` | file name/type/MIME/size, family signature, delivery method, ClamAV signatures, hashes | 20 / min | [abuse.ch MalwareBazaar API](https://bazaar.abuse.ch/api/) |

Defaults are conservative guesses aligned with each vendor's free tier; override with `HUNTERINTEL_PROVIDER_RATE_LIMITS="virustotal=4/60,crtsh=1/3"`. Limits are enforced by a sliding window (shared through Redis when configured) **before** a request is made; a wait longer than 15 s becomes a `rate_limited` run instead of blocking the analyst.

Notes:

* **abuse.ch** now requires a free `Auth-Key` for URLhaus and MalwareBazaar (one key covers both). This was confirmed from secondary sources only.
* **VirusTotal / OTX / URLhaus / MalwareBazaar never receive a file.** The only VirusTotal verbs used are read-only `GET`s; there is no code path to its upload or URL-scan endpoints, and a test asserts that no provider ever sends a multipart/binary body.
* **OTX** pulses are community content and noisy, so OTX alone can raise at most a *suspicious*, low-weight signal.
* **AbuseIPDB** `score 0` means "no reports", not "benign"; only the vendor allow-list yields a harmless signal.

## Writing a provider

```python
from hunterintel.core.ratelimit import RateSpec
from hunterintel.domain.evidence import Assurance, ObservationDraft, ProviderResult, ReputationSignal, Tier
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator
from hunterintel.providers.base import Provider, ProviderContext, map_http_status
from hunterintel.providers.signals import reputation_observation


class ExampleFeedProvider(Provider):
    name = "examplefeed"                       # unique, used in API/UI/DB
    display_name = "Example Feed"
    description = "What it provides, in one sentence."
    tier = Tier.THIRD_PARTY                    # how far the indicator travels
    supported_types = frozenset({IndicatorType.DOMAIN, IndicatorType.IP})
    key_env = "EXAMPLEFEED_API_KEY"            # shown in the UI when unconfigured
    reliability = 0.6                          # your trust in its malicious verdicts, 0..1
    default_rate = RateSpec(30, 60.0)          # requests / seconds
    allowed_hosts = ("api.examplefeed.test",)  # the gateway refuses anything else

    def is_configured(self) -> bool:           # add the SecretStr field to Settings first
        return self.settings.examplefeed_api_key is not None

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        resp = await ctx.http.request(          # the ONLY way to make HTTP calls
            "GET", f"https://api.examplefeed.test/v1/{parsed.value}",
            provider=self.name, rate=self.rate(), allowed_hosts=self.allowed_hosts,
            headers={"Authorization": self.settings.examplefeed_api_key.get_secret_value()},
            cache_ttl=ctx.settings.cache_ttl_seconds, refresh=ctx.refresh,
        )
        if (failure := map_http_status("Example Feed", resp)) is not None:
            return failure                      # 404 → no_data, 429 → rate_limited, 401 → error …
        doc = resp.json()
        signal = ReputationSignal(source=self.name, verdict="malicious" if doc["bad"] else "unknown",
                                  strength=0.8 if doc["bad"] else 0.0, reliability=self.reliability,
                                  label=f"{doc['hits']} sightings", definitive=doc["bad"])
        return ProviderResult.ok(observations=[reputation_observation(self.display_name, signal)])
```

Then register it in `providers/registry.py`. Rules of the road:

1. Label honestly: `VERIFIED` only for first-hand/authoritative or locally computed facts, `PROVIDER_CLAIM` for anything a third party says, `INFERRED` for your own heuristics.
2. A miss is `ProviderResult.no_data(...)`, **not** a clean verdict. Only emit a `harmless` signal when the source makes a definitive negative statement.
3. Never put a secret in a URL or log line; use headers. The gateway redacts errors, but don't test it.
4. Bound everything: cap list lengths, set `truncated=True` when you cut, keep `data` JSON-able.
5. Add tests with a `httpx.MockTransport` (see `tests/test_providers_keyed.py`) including the 404 / 429 / 401 / garbage-body cases.
