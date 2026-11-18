# 05 · IOC lookup form

Paste an IP, domain, URL or file hash into a form and check it everywhere at once: **VirusTotal, AbuseIPDB, MISP, OpenCTI and your own Wazuh alerts** from the last 30 days. You get one combined verdict on screen and a full report by email.

```
Form (IOC)
  → Detect IOC
  → VirusTotal
  → Is public IP? ── true ──→ AbuseIPDB ─┐
                  └─ false ──────────────┴→ MISP → OpenCTI → Wazuh
  → Build verdict → Send Email → Form ending (summary on screen)
```

**What it accepts:** IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256 hashes – including **defanged** values like `hxxps://example[.]com` or `1.2.3[.]4`, the way IOCs are usually shared in reports. The email shows IOCs defanged too, so nothing can be clicked by accident.

**Verdicts**

| Verdict | Meaning |
|---------|---------|
| MALICIOUS | At least one source flags it as bad |
| SUSPICIOUS | Some concern, not confirmed |
| NO KNOWN THREAT | All sources answered and none flags it. It never says "safe" – nothing known isn't proof of harmless. |
| INCOMPLETE CHECK | Nothing bad found, but one or more sources didn't answer. The report says which. |
| NOT CHECKED | No source returned a usable answer |

**Prerequisites:** [00-setup](../00-setup/) with the **SMTP, Wazuh indexer, VirusTotal, AbuseIPDB, MISP** and **OpenCTI** credentials. Free API keys: [VirusTotal](https://www.virustotal.com/gui/join-us), [AbuseIPDB](https://www.abuseipdb.com/register).

**Files**

| File | Used in |
|------|---------|
| `detect-ioc.js` | Code node **Detect IOC** – cleans the input, works out its type, prepares every request |
| `build-verdict.js` | Code node **Build verdict** – reads every source and builds the verdict and email |

---

## Step 1 · Build the workflow

Create a workflow named **IOC lookup**.

> **Name the nodes exactly as shown** (`Detect IOC`, `VirusTotal`, `AbuseIPDB`, `MISP`, `OpenCTI`, `Wazuh`). Build verdict reads each one by name. In my first test, two misnamed nodes made the lookup say "no known threat" while those sources had never been read.

**1. n8n Form Trigger**

| Setting | Value |
|---------|-------|
| Form Title | `IOC lookup` |
| Field | Label **`IOC`** · Type *Text* · required |
| Respond When | Workflow Finishes |
| Authentication | Basic Auth (recommended) |

**2. Code → `Detect IOC`** – paste `detect-ioc.js`.

**3. The five source nodes** (all HTTP Request). Give **every one** of them these settings so one failing source never stops the others:

- **Options → Response → Include Response Headers and Status:** on
- **Options → Response → Never Error:** on
- **Settings → On Error:** Continue

| Node name | Method & URL | Authentication | Body / query |
|-----------|--------------|----------------|--------------|
| **VirusTotal** | GET `https://www.virustotal.com/api/v3/{{ $('Detect IOC').first().json.vtPath }}` | Header Auth → VirusTotal | – |
| **AbuseIPDB** | GET `https://api.abuseipdb.com/api/v2/check` | Header Auth → AbuseIPDB | Query: `ipAddress` = `{{ $('Detect IOC').first().json.ioc }}`, `maxAgeInDays` = `90`. Header `Accept: application/json` |
| **MISP** | POST `<MISP_URL>/attributes/restSearch` | Header Auth → MISP | Header `Accept: application/json`. JSON body `{{ JSON.stringify($('Detect IOC').first().json.mispBody) }}` |
| **OpenCTI** | POST `<OPENCTI_URL>/graphql` | Header Auth → OpenCTI | JSON body `{{ JSON.stringify($('Detect IOC').first().json.openctiBody) }}`. Options → Timeout `5000` |
| **Wazuh** | POST `https://127.0.0.1:9200/wazuh-alerts-*/_search` | Basic Auth → Wazuh indexer | JSON body `{{ JSON.stringify($('Detect IOC').first().json.wazuhQuery) }}`. Ignore SSL Issues on |

**4. If → `Is public IP?`** – placed after VirusTotal

| Setting | Value |
|---------|-------|
| Condition | `{{ $('Detect IOC').first().json.isPublicIP }}` · Boolean **is true** |
| true → | AbuseIPDB → MISP |
| false → | MISP (AbuseIPDB only knows public IPs) |

**5. Code → `Build verdict`** – paste `build-verdict.js`. Connect it after **Wazuh**.

**6. Send Email** – Subject `{{ $json.subject }}`, Email Format HTML, HTML `{{ $json.html }}`.

**7. Form ending** – add an **n8n Form** node set to *Form Ending* (completion page) and show `{{ $('Build verdict').first().json.summary }}` as its text.

**Save** and **Publish**, then open the form's Production URL.

## Step 2 · Test

| Try | Expected |
|-----|----------|
| A known Tor exit node or an IP with many AbuseIPDB reports | MALICIOUS – in my test 16/91 VirusTotal engines, AbuseIPDB 100%, and six records in my own MISP feeds |
| `8.8.8.8` | NO KNOWN THREAT |
| A private IP like `10.0.0.5` | AbuseIPDB skipped; only MISP/OpenCTI/Wazuh checked |
| A defanged URL `hxxps://example[.]com` | Accepted and refanged |
| Stop OpenCTI and look up anything | INCOMPLETE CHECK, naming OpenCTI |

## Troubleshooting

| Source shows | Fix |
|--------------|-----|
| "rejected the API key (HTTP 401/403)" | Wrong or missing credential on that node |
| "No answer from a node named …" | The node is misnamed or not connected |
| OpenCTI "did not accept the API token" | The credential value must be `Bearer ` + token. Re-copy the token carefully (case matters). |
| VirusTotal HTTP 429 | Free API limit is 4 lookups per minute |
