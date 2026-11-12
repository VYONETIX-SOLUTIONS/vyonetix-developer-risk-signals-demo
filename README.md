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

The RapidAPI project is currently private while its owner completes the platform's rights-to-publish attestation. The three routes are deployed and passed gateway checks, but new external consumers cannot subscribe yet. No key is included here. Once public access is enabled, the API will be discoverable through the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals).

## Sources and rights

- Upstream catalog: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Data licence: [CISA KEV CC0 1.0 licence](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- Attribution: CISA Known Exploited Vulnerabilities Catalog; no CISA endorsement implied.

The reduced catalog fields in the sample are published under CC0 1.0. Do not use CISA or DHS seals/logos or imply endorsement.

Follow product release notes on [Telegram](https://t.me/vyonetix_api_signals). Vyonetix Developer Risk Signals is a controlled pilot without an availability SLA.
