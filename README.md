# VYONETIX-SOLUTIONS — Developer Risk Signals

**Normalize three public software-risk sources into one developer-friendly API contract.** Filter CISA's Known Exploited Vulnerabilities (KEV) catalog, check caller-supplied package versions against OSV, and match exact OpenSSF malicious-package reports.

[Open the RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals) · [View the free JSON sample](https://sudheer-vyo.github.io/vyonetix-developer-risk-signals-demo/) · [Try the GitHub Action](https://github.com/sudheer-vyo/vyonetix-developer-risk-signals-demo/tree/main/integrations/github-action)

> This is a controlled pilot without an availability SLA. The API returns source-linked evidence, not an exploitability or safety verdict. A no-match does not mean a dependency is safe.

## What it does

| Operation | Use |
|---|---|
| `GET /v1/security/kev` | Filter reduced CISA KEV catalog facts by date, CVE, vendor, or product with bounded pagination. |
| `POST /v1/dependencies/check` | Check up to the documented batch limit of caller-supplied package coordinates and versions against OSV. |
| `POST /v1/packages/malicious-check` | Find exact package/version matches in OpenSSF MAL reports. |

One normalized response envelope keeps status, timestamps, source provenance, license notes, and result data together. The service accepts package coordinates, not uploaded SBOM files.

## Start with one request

Subscribe or choose a plan on the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals), copy your consumer key, and set it in your shell as `RAPIDAPI_KEY`. Keep the key in a secret manager or environment variable; never commit it.

The listing currently shows a 100-request monthly Basic plan, a US$19/month Pro plan, and a US$39/month Ultra plan. Plan limits and card requirements can change; review the listing before subscribing. RapidAPI's current Freemium arrangement may require a payment card even for Basic.

```sh
curl --get 'https://vyonetix-developer-risk-signals.p.rapidapi.com/v1/security/kev' \
  --data-urlencode 'since=2026-11-01' \
  --data-urlencode 'limit=3' \
  -H "X-RapidAPI-Key: ${RAPIDAPI_KEY}" \
  -H 'X-RapidAPI-Host: vyonetix-developer-risk-signals.p.rapidapi.com' \
  -H 'Accept: application/json'
```

For payloads and complete examples, see [samples/quickstart.md](samples/quickstart.md).

## GitHub Actions integration

The early-access [CycloneDX Action](integrations/github-action/) sends up to 50 supported package/version tuples to the API and can optionally make a second request for exact OpenSSF checks. It writes aggregate counts to the job summary.

- [Read the Action guide](integrations/github-action/README.md)
- [Copy the example workflow](integrations/github-action/example-workflow.yml)
- Pin the reviewed Action commit shown in the example; review updates before changing that pin.
- The Action is an early-access source release, **not** a GitHub Marketplace listing.
- Package names and versions are transmitted to RapidAPI and OSV. Do not use private package identifiers, confidential inventories, or sensitive SBOM metadata.
- Findings are review evidence only. The Action does not determine exploitability and does not fail a job by default.

## Free data example

[Download the timestamped JSON fixture](kev-latest-sample.json) or use the [sample page](https://sudheer-vyo.github.io/vyonetix-developer-risk-signals-demo/). It contains three reduced records from the public CISA KEV catalog. This is a static snapshot, **not a live Vyonetix API response**. Check its observation time before reuse.

CISA KEV catalog facts in the fixture are published under [CC0 1.0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt), with attribution to the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). No CISA/DHS marks are used, and no CISA endorsement is implied.

## Data and limitations

- KEV fields are reduced catalog facts. OSV and OpenSSF results are limited to identifiers, timestamps, exact-match status, and source links because upstream record rights vary.
- Package coordinates are sent to RapidAPI and OSV for matching. Do not submit confidential dependency inventories.
- A match means a source record matched the submitted coordinates. It does not establish that software is reachable, exploitable, malicious in a given environment, or safe.
- The service is a controlled `workers.dev` pilot. No SLA or guaranteed response time is offered.
- The API routes passed authenticated RapidAPI gateway checks on 12 November 2026. Independent customer signup, metering, and CI execution remain unverified.

## Sources

- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [CC0 1.0 licence](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- [OSV database and source licences](https://google.github.io/osv.dev/data/)
- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)

## Support and updates

Use [GitHub Issues](https://github.com/sudheer-vyo/vyonetix-developer-risk-signals-demo/issues) for reproducible documentation or integration problems. Check the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals) for current plan availability and service documentation.

**VYONETIX-SOLUTIONS** · Public data, source-linked results, bounded claims.
