# Vyonetix Developer Risk Signals — free data and API sample

**RapidAPI listing:** [Vyonetix Developer Risk Signals](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals)  
**Sample page:** [Open the CISA KEV JSON example](https://vyonetix-solutions.github.io/vyonetix-developer-risk-signals-demo/)  
**Current access:** the public listing currently shows a free BASIC plan with a 1,000-request monthly quota and a legacy deprecated plan. No paid DRS plan is currently listed. Check the RapidAPI page for current plan details.

## What you can try without an API key

The included [`kev-latest-sample.json`](kev-latest-sample.json) is a timestamped, reduced snapshot of the public CISA Known Exploited Vulnerabilities catalog. It demonstrates response shape and provenance. It is **not** a live Vyonetix API response. The [`epss-kev-live-sample.json`](epss-kev-live-sample.json) file is a captured, source-attributed response from the primary Worker for the EPSS + KEV route; its `checked_at` field records capture time. It is not an independent RapidAPI gateway response. The sample page includes a direct `curl` command for the public CISA feed.

## What the API does

- `GET /v1/security/kev` — filter reduced CISA catalog fields by date, CVE, vendor, or product.
- `POST /v1/security/prioritize` — combine caller-supplied CVE IDs with FIRST EPSS daily fields and CISA KEV membership.
- `POST /v1/dependencies/check` — submit up to 50 package coordinates to OSV and receive advisory IDs, timestamps, and links.
- `POST /v1/packages/malicious-check` — exact version-aware matches to OSV reports in the OpenSSF `MAL-` namespace.

The primary Worker is a controlled `workers.dev` pilot without an availability SLA. The timestamped EPSS + KEV sample above demonstrates its response shape and source metadata; it is not a live gateway result.

## Call the live marketplace API

Choose BASIC on the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals), use your own consumer key from an environment variable, and follow the [four-route quickstart](https://github.com/VYONETIX-SOLUTIONS/vyonetix-developer-risk-signals-demo/blob/main/quickstart.md). Do not put a key in source code or screenshots.

```sh
curl 'https://vyonetix-developer-risk-signals.p.rapidapi.com/v1/security/prioritize' \
  -H 'Content-Type: application/json' \
  -H "X-RapidAPI-Key: ${RAPIDAPI_KEY}" \
  -H 'X-RapidAPI-Host: vyonetix-developer-risk-signals.p.rapidapi.com' \
  -d '{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}'
```

The service returns evidence, not an asset-specific risk score or safety decision. FIRST receives the CVE IDs submitted to prioritization; EPSS content is provided solely for preventative cybersecurity use. Package coordinates are sent to OSV. Never send confidential package inventories or private SBOM metadata. A no-match does not prove safety.

## Sources and rights

- CISA KEV reduced catalog fields: [CC0 1.0 licence](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt). Attribution is retained; no CISA endorsement is implied.
- FIRST EPSS: [EPSS information](https://www.first.org/epss/); preventative cybersecurity use only, with attribution.
- OSV.dev: [API documentation](https://google.github.io/osv.dev/post-v1-querybatch/). Upstream records have mixed licensing; this product returns bounded identifiers and links rather than advisory bodies.
- OpenSSF: [Malicious Packages](https://github.com/ossf/malicious-packages). This product matches exact `MAL-` identifiers and returns source links.

See [the API overview](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals) and [Vyonetix API Signals on Telegram](https://t.me/vyonetix_api_signals) for updates.
