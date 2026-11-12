# Free CISA KEV Data Sample — Vyonetix Developer Risk Signals

**Interactive sample page:** [Developer Risk Signals — Free KEV JSON Sample](https://sudheer-vyo.github.io/vyonetix-developer-risk-signals-demo/)

This repository contains a small, time-stamped JSON sample derived from the public CISA Known Exploited Vulnerabilities (KEV) catalog. It shows the reduced response shape used by Vyonetix Developer Risk Signals: CVE, vendor, product, catalog dates, source attribution, and freshness metadata.

## Try the public source for free

The Vyonetix fixture is a snapshot. To inspect the live upstream feed directly, use:

```sh
curl -fsSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq '{catalogVersion, dateReleased, count, vulnerabilities: [.vulnerabilities[:3][] | {cveID, vendorProject, product, dateAdded, dueDate, knownRansomwareCampaignUse}]}'
```

The Vyonetix-style sample is in [`kev-latest-sample.json`](kev-latest-sample.json). It is captured from the upstream catalog and is **not a live response from the Vyonetix API**. Check its `checked_at` and `source_metadata.source_updated_at` before reusing it.

## What the API does

The API provides one consistent JSON envelope and supports filters such as `since`, `cve_id`, `vendor`, and `product`, plus bounded pagination. It retains source provenance and timestamps. It does not decide whether a CVE affects a particular system, assess exploitability, or issue a security verdict.

The [RapidAPI listing is public](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals). Three REST routes are deployed and previously passed authenticated gateway checks. No key is included here. The public listing combines free and paid plans; RapidAPI classifies this as Freemium and requires a payment card even for the free tier. The sample remains a static upstream CISA snapshot, not a live Vyonetix response.

## Try it from GitHub Actions

An early-access [CycloneDX GitHub Action](https://github.com/sudheer-vyo/vyonetix-developer-risk-signals-demo/tree/main/integrations/github-action) sends up to 50 supported package/version tuples to the public RapidAPI service and writes aggregate match counts to the job summary. It requires the caller's RapidAPI consumer key, makes one request by default (two when exact OpenSSF checks are enabled), and must not be used with confidential SBOM identifiers. The local parser/self-check passed; an independent consumer CI run has not been verified. Review the Action's privacy and limitation notes before use.

## Sources and rights

- Upstream catalog: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Data licence: [CISA KEV CC0 1.0 licence](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- Attribution: CISA Known Exploited Vulnerabilities Catalog; no CISA endorsement implied.

The reduced catalog fields in the sample are published under CC0 1.0. Do not use CISA or DHS seals/logos or imply endorsement.

Follow product release notes on [Telegram](https://t.me/vyonetix_api_signals). Vyonetix Developer Risk Signals is a controlled pilot without an availability SLA.
