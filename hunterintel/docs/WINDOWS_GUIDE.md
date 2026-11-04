# HunterIntel on Windows — setup and user guide

For Windows 10 / 11. It covers installing and starting HunterIntel, then a tour of how to actually investigate with it.

> **Status of these instructions.** HunterIntel was developed and tested on Linux. The commands below use standard Windows tooling (PowerShell, Docker Desktop, WSL2, Python, Node), but they have **not been run on a Windows machine by the author**. If something fails, check [Troubleshooting](#8-troubleshooting) first, and please open an issue with the exact error.

---

## 1. Pick how to run it

| Option | Best for | Effort | Notes |
|---|---|---|---|
| **A. Docker Desktop** | Just using it | Lowest | One command starts the API, web UI, PostgreSQL and Redis. Recommended. |
| **B. WSL2 (Ubuntu)** | Developing / most similar to the tested setup | Medium | Runs the real Linux environment inside Windows. |
| **C. Native PowerShell** | Developing without Docker/WSL | Medium | Works with Python + Node installed directly. SQLite database, no Redis. |

Not sure? Use **A**.

## 2. Install the prerequisites

| Tool | Needed for | Get it | Check |
|---|---|---|---|
| **Git for Windows** | all | <https://git-scm.com/download/win> | `git --version` |
| **Docker Desktop** (with the WSL2 backend) | option A | <https://www.docker.com/products/docker-desktop/> | `docker --version` |
| **Python 3.12 or newer** | option C (and the sample loader) | <https://www.python.org/downloads/windows/> — tick **“Add python.exe to PATH”** | `py -3.12 --version` |
| **Node.js 20+ (LTS)** | option C | <https://nodejs.org/> | `node --version` |

Use **PowerShell** (Start → “PowerShell”) for every command below.

## 3. Get the code

```powershell
cd $HOME
git clone https://github.com/milosz6432/misc.git
cd misc
git checkout claude/eager-meitner-1u5ix8     # only until the pull request is merged; afterwards use: git checkout main; git pull
cd hunterintel
```

Everything below is run from this `hunterintel` folder unless a step says otherwise.

---

## 4A. Run with Docker Desktop (recommended)

1. Start **Docker Desktop** and wait until it says it is running.
2. Create your settings file and set a database password:

   ```powershell
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(32))"    # prints a random value; copy it
   notepad .env
   ```

   In Notepad, set `POSTGRES_PASSWORD=` to that value and save. (Optional: also set `HUNTERINTEL_API_TOKEN=` to another random value if you want the API to require a login token.)
3. Build and start everything (the first build takes several minutes):

   ```powershell
   docker compose up --build
   ```
4. Open **<http://127.0.0.1:8080>**.

Day-to-day:

| Task | Command |
|---|---|
| Stop | `Ctrl+C` in the window, then `docker compose down` |
| Start again (no rebuild) | `docker compose up -d` |
| Apply a changed `.env` | `docker compose up -d` (recreates the containers) |
| Update after `git pull` | `docker compose up --build -d` |
| Delete all stored data | `docker compose down -v` |

Only the web UI is published, and only to your own PC (`127.0.0.1`). Don't expose it to a network without HTTPS in front and `HUNTERINTEL_API_TOKEN` set.

## 4B. Run inside WSL2

1. In PowerShell (as administrator): `wsl --install -d Ubuntu`, then reboot if asked and create your Linux user.
2. Inside the Ubuntu terminal, work in your Linux home folder (`~`), **not** under `/mnt/c`:

   ```bash
   sudo apt update && sudo apt install -y git python3.12 python3.12-venv curl
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs
   git clone https://github.com/milosz6432/misc.git && cd misc/hunterintel
   git checkout claude/eager-meitner-1u5ix8      # until the PR is merged
   ```
3. Follow **“Local development”** in the main [README](../README.md#quick-start). Browse from Windows to `http://localhost:5173` (WSL2 forwards localhost automatically).

## 4C. Run natively in PowerShell

You need **two PowerShell windows**: one for the backend (API), one for the frontend (web UI).

### Window 1 — backend

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
uvicorn hunterintel.api.app:app_factory --factory --host 127.0.0.1 --port 8000 --reload
```

Check that **<http://127.0.0.1:8000/docs>** opens. A `hunterintel.db` file is created in `backend\` (your SQLite database).

> If `Activate.ps1` is blocked (“running scripts is disabled”), run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once and retry — or skip activation and prefix tools with the venv path, e.g. `.\.venv\Scripts\python.exe -m pip install -e ".[dev]"` and `.\.venv\Scripts\uvicorn.exe hunterintel.api.app:app_factory --factory --host 127.0.0.1 --port 8000`.

### Window 2 — frontend

```powershell
cd frontend
npm install
npm run dev
```

Open **<http://localhost:5173>**. (The dev server forwards `/api` calls to `http://127.0.0.1:8000`.)

### Optional settings for the native route

The backend reads a `.env` file from the folder it is started in:

```powershell
cd backend
Copy-Item ..\.env.example .env
notepad .env          # uncomment / fill in what you need, save, then restart uvicorn
```

Or set values for the current window only (restart uvicorn afterwards):

```powershell
$env:VIRUSTOTAL_API_KEY = "paste-key-here"
```

`.env` is ignored by Git; never commit it.

> Windows may show a **Firewall** prompt for Python or Node. Everything here runs on `127.0.0.1`, so you can choose *Cancel* / private networks only.

---

## 5. Using HunterIntel — a ten-minute tour

The key idea: **nothing is sent anywhere until you choose it.** Searching only *parses* your input locally and shows a plan.

### 5.1 Search and the query plan

Press **Ctrl+K** (or click the search box) and paste an indicator. It accepts:

| You paste | It understands |
|---|---|
| `example.com`, `*.example.com`, `bücher.de` | domain (wildcards and IDN handled) |
| `1.1.1.1`, `2606:4700:4700::1111` | IPv4 / IPv6 |
| `https://example.com/a?b=1`, `hxxps://evil[.]com/x` | URL (defanged links are restored) |
| a 32 / 40 / 64-character hex string | MD5 / SHA-1 / SHA-256 file hash |
| `AS13335` | AS number |
| `analyst@example.com` | e-mail (only the **domain part** is ever looked up) |
| `cert:<64-hex>` or `crtsh:12345` | certificate (a bare 64-hex string is treated as a file hash) |

You land on the **Query plan** page. It shows:

* what it recognised (and an **“Interpret as”** row if you want to override it);
* every source that *could* receive it, grouped by how far the data travels — **Stays on this host**, **Public infrastructure**, **Third-party vendors (API key)**, **Active probe**;
* for each, exactly **what it would send**, or **why it is unavailable** (not configured / blocked).

Tick what you are comfortable sharing and press **Run**, or press **Local analysis only** to send nothing.

*Private, internal and reserved indicators* (`10.0.0.5`, `server.corp.internal`, `http://192.168.1.10/…`) are blocked from every remote source automatically. That is a safety feature, not a bug.

### 5.2 The indicator page

* **Header** — type, verdict, freshness, your classification, and *do not share* if set.
* **Overview** — **Key facts** (each with its source and a badge), **Risk indicators** (heuristics), and **Unavailable information** (sources that were blocked, missing a key, rate-limited, timed out or errored — gaps are always shown).
* **Provider results** — one card per source with its run status; expand an item for the full data; **“finding”** saves it into an investigation.
* **Relationships** — the graph. Click a node or edge for details. Line style shows trust: **solid = verified, dashed = provider claim, dotted = inferred**. Zoom in for edge labels. Use *Depth* to widen it.
* **History** — every earlier version of each observation (for example, DNS changes), plus a log of every provider run.
* **Assessment panel** — risk, confidence, and *How this was scored*, listing each contribution.
* **Analyst panel** — set your own classification, add tags, or tick **Do not share** to lock the indicator to local analysis only.

### 5.3 How to read the badges

| Badge | Meaning |
|---|---|
| **Verified** | Observed first-hand from the source of record (DNS answer, registry RDAP, live probe) or computed locally. |
| **Provider claim** | A third party says so. Always attributed; not independently confirmed. |
| **Inferred** | HunterIntel derived it (heuristics, shared infrastructure). A lead, not proof. |

| Verdict | Meaning |
|---|---|
| **Malicious / Suspicious** | Reputation sources reported it, weighted by their reliability and age. |
| **Low risk** | Weak signals only (for example, structural heuristics). |
| **No detections** | A source made a definitive negative statement. It is *not* proof of safety. |
| **Unknown** | No source made a determination (or the evidence expired). **Unknown does not mean safe.** |

### 5.4 Investigations (the workspace)

1. **Investigations → Create**, give it a title and a **TLP** level. At **TLP:RED** or **TLP:AMBER+STRICT**, every indicator you add is automatically marked *do not share*.
2. Add indicators: on the investigation (type one in) or from an indicator page (**Add to investigation**). Adding does not contact anyone.
3. On an indicator's **Provider results** tab, press **“finding”** next to an observation to save it with a *snapshot* of the evidence — later re-enrichment will not change what you recorded.
4. Use the **Notes**, **Graph** and **Compare** tabs. *Compare* (tick two or more indicators) shows shared infrastructure, tags and attributes, graded weak / medium / strong — remember these overlaps are leads, not attribution.
5. **Export report** as **Markdown**, **HTML** (print to PDF from your browser) or **JSON**. Keep **defang indicators** ticked so links in the report can’t be clicked by accident.

### 5.5 Local tools — hash a file

**Local tools → Hash a file.** Choose or drop a file: it is hashed in memory on *your own* server and discarded; it is never stored or uploaded to VirusTotal or anyone else. You get MD5/SHA-1/SHA-256 and a best-effort file type. Then **Investigate this SHA-256…** takes you to the query plan, where you decide whether to look the *hash* up anywhere.

> Windows Defender will quarantine the real EICAR test file if you download it — that is expected. The bundled samples use only its *hashes*, which are harmless.

### 5.6 Other pages

* **Indicators** — everything you have investigated; filter by type, verdict, tag, or text; expired items are hidden unless you tick *include expired*.
* **Dashboard** — counts, verdict distribution, recent activity and **recent provider problems**.
* **Providers** — which sources are ready, what each receives, rate limits and terms links.

### 5.7 Try the sample investigations

With the backend running, from the `hunterintel` folder:

```powershell
# creates the investigation only — sends nothing
python scripts\load_sample.py samples\01-getting-started.json

# also runs the keyless public sources
python scripts\load_sample.py samples\01-getting-started.json --enrich

# shows the safety controls (everything stays local)
python scripts\load_sample.py samples\03-policy-demo-private-indicators.json --enrich
```

* **Docker route:** the API is not published directly, so point the script at the web container: add `--api http://127.0.0.1:8080` (and `--token <your token>` if you set one).
* The samples contain seed indicators only. Everything shown comes from live sources when you run it. Providers that send data to third parties additionally need `--yes`.

---

## 6. Add API keys (optional)

HunterIntel works without any keys (DNS, RDAP, certificate transparency, Team Cymru, local analysis). Keys add reputation sources:

| Provider | Get a key | Setting |
|---|---|---|
| VirusTotal | <https://www.virustotal.com/gui/my-apikey> | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB | <https://www.abuseipdb.com/account/api> | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | <https://otx.alienvault.com/settings> | `OTX_API_KEY` |
| URLhaus + MalwareBazaar | <https://auth.abuse.ch/> (one free key covers both) | `ABUSECH_AUTH_KEY` |

* **Docker:** put the key in `.env` next to `docker-compose.yml`, then `docker compose up -d`.
* **Native:** put it in `backend\.env` (or `$env:NAME = "…"`), then restart uvicorn.

Then open **Providers** — it should say *ready*. Keyed sources are **never pre-ticked**; you tick them in the query plan for each lookup. Respect each vendor's terms and quotas (for example, VirusTotal's public API is limited and non-commercial).

## 7. Settings you may want

| Setting | What it does |
|---|---|
| `HUNTERINTEL_API_TOKEN` | Require a login token for the API (the UI will ask for it once per browser tab). |
| `HUNTERINTEL_DNS_RESOLVERS` | DNS servers used for lookups, default `1.1.1.1,9.9.9.9`. Set your own if those are blocked on your network. |
| `HUNTERINTEL_ALLOW_ACTIVE_PROBES` | `true` enables the redirect-chain probe (HunterIntel itself contacts the target — only where you are permitted to). |
| `HUNTERINTEL_DEFAULT_SHARING` | `third_party` pre-ticks keyed vendors in plans. Leave at `public` unless you understand the privacy trade-off. |
| `HUNTERINTEL_PROVIDER_RATE_LIMITS` | Tighten per-provider limits, e.g. `virustotal=2/60`. |

All settings are listed in [`.env.example`](../.env.example).

---

## 8. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `py` or `python` not found | Reinstall Python and tick **Add python.exe to PATH**; reopen PowerShell. `py -0` lists installed versions — you need 3.12+. |
| `Activate.ps1 cannot be loaded … scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or call the venv's executables directly (see 4C). |
| `pip install` fails compiling a package | Rare (wheels exist for Windows). Upgrade pip first (`python -m pip install --upgrade pip`); as a last resort install *Microsoft C++ Build Tools*. |
| Web page loads but every action shows an error / “proxy error” in the `npm run dev` window | The backend isn't running on `127.0.0.1:8000`. Start it (Window 1), then reload. After a `git pull`, restart `npm run dev` too. |
| `Address already in use` / port 8000 or 5173 busy | `netstat -ano \| findstr :8000`, then `taskkill /PID <pid> /F`. Or use another port: `--port 8001` and, in the frontend window, `$env:VITE_API_TARGET = "http://127.0.0.1:8001"` before `npm run dev`. |
| Docker: *“set POSTGRES_PASSWORD in .env”* | Create `.env` (step 4A.2) in the same folder as `docker-compose.yml` and set a value. |
| Docker: daemon not running / build fails immediately | Start Docker Desktop and wait for “running”; ensure the WSL2 backend is enabled. |
| Docker: port 8080 already used | Edit `docker-compose.yml`, `ports:` of the `web` service (e.g. `"127.0.0.1:8081:8080"`). |
| Everything resolves to **NXDOMAIN** or DNS times out | UDP port 53 to `1.1.1.1` / `9.9.9.9` is blocked or intercepted (common on corporate networks, VPNs, captive portals). Set `HUNTERINTEL_DNS_RESOLVERS` to your network's DNS server. The UI labels NXDOMAIN as “per the configured resolvers”. |
| RDAP / crt.sh / vendor results show **“cannot resolve”, “ConnectError” or “timed out”** | HunterIntel needs **direct HTTPS access**; by design it does **not** use Windows/system proxy settings. Behind a mandatory corporate proxy these sources can't be reached — ask IT to allow them, or run on a network without the proxy. This is reported as an error, never as an empty result. |
| crt.sh “overloaded” / non-JSON / too large | Normal for popular domains (it is a volunteer service). Retry later or investigate a more specific sub-domain. |
| UI asks for an **API token** | You set `HUNTERINTEL_API_TOKEN`. Paste it; it is kept only for that browser tab. |
| `curl` behaves strangely in PowerShell | `curl` is an alias for `Invoke-WebRequest`. Use **`curl.exe`**. |
| Odd characters / `UnicodeEncodeError` from the sample script | `$env:PYTHONUTF8 = "1"` then rerun. |
| Strange database errors right after updating (native route) | The local SQLite file may predate a schema change. Stop the backend and delete `backend\hunterintel.db*` (development data is disposable). Docker/PostgreSQL migrates automatically on start. |

## 9. Stop, reset, update, test

* **Stop:** `Ctrl+C` in each window (Docker: also `docker compose down`).
* **Reset all data:** native — delete `backend\hunterintel.db*`; Docker — `docker compose down -v`.
* **Update:** `git pull`, then reinstall (`pip install -e ".[dev]"` in `backend`, `npm install` in `frontend`) or `docker compose up --build -d`.
* **Run the tests (native):** in `backend` with the venv active, `pytest -q`; in `frontend`, `npm test`.

More detail: [Architecture](ARCHITECTURE.md) · [API](API.md) · [Providers](PROVIDERS.md) · [Security](SECURITY.md).
