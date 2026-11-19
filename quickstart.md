# Developer Risk Signals API quickstart

**Marketplace:** [Vyonetix Developer Risk Signals on RapidAPI](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals)

The listing currently shows a free BASIC plan with 1,000 requests/month and a legacy `BASIC Deprecated` card. No paid DRS tier is currently listed. Follow the live listing for current plan, signup, and usage terms.

## Start here: enrich CVE identifiers

Choose BASIC in RapidAPI and copy your own consumer key into a local environment variable. Do not commit it.

```sh
export RAPIDAPI_KEY='your-consumer-key'
curl 'https://vyonetix-developer-risk-signals.p.rapidapi.com/v1/security/prioritize' \
  -H 'Content-Type: application/json' \
  -H "X-RapidAPI-Key: ${RAPIDAPI_KEY}" \
  -H 'X-RapidAPI-Host: vyonetix-developer-risk-signals.p.rapidapi.com' \
  -d '{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}'
```

The response combines FIRST EPSS daily probability/percentile fields with CISA KEV membership/date and returns source dates, provenance, and a UTC check time. The sample file [`epss-kev-live-sample.json`](epss-kev-live-sample.json) is a captured primary-Worker response with its own timestamp; it is not a live gateway result or independent consumer test.

FIRST receives supplied CVE identifiers. EPSS is a daily probability estimate for observed exploitation activity, not impact or asset exposure, and this route is for preventative cybersecurity use. Results are deterministic source-signal ordering, not a full risk score.

## Other operations

### Filter the reduced CISA KEV catalog

```sh
curl --get 'https://vyonetix-developer-risk-signals.p.rapidapi.com/v1/security/kev' \
  --data-urlencode 'since=2026-11-01' --data-urlencode 'limit=20' \
  -H "X-RapidAPI-Key: ${RAPIDAPI_KEY}" \
  -H 'X-RapidAPI-Host: vyonetix-developer-risk-signals.p.rapidapi.com'
```

Optional query parameters: `since`, `cve_id`, `vendor`, `product`, `limit`, and `offset`.

### Check package versions through OSV

```sh
curl 'https://vyonetix-developer-risk-signals.p.rapidapi.com/v1/dependencies/check' \
  -H 'Content-Type: application/json' -H "X-RapidAPI-Key: ${RAPIDAPI_KEY}" \
  -H 'X-RapidAPI-Host: vyonetix-developer-risk-signals.p.rapidapi.com' \
  -d '{"packages":[{"ecosystem":"npm","name":"lodash","version":"4.17.20"}]}'
```

### Match exact OpenSSF malicious-package reports

```sh
curl 'https://vyonetix-developer-risk-signals.p.rapidapi.com/v1/packages/malicious-check' \
  -H 'Content-Type: application/json' -H "X-RapidAPI-Key: ${RAPIDAPI_KEY}" \
  -H 'X-RapidAPI-Host: vyonetix-developer-risk-signals.p.rapidapi.com' \
  -d '{"packages":[{"ecosystem":"npm","name":"event-stream","version":"3.3.6"}]}'
```

The package endpoints accept up to 50 supported ecosystem/name/version tuples. Package coordinates are sent to OSV; do not submit private package names, confidential SBOMs, or secrets. A no-match is not proof that a package is safe. The API provides evidence and links, not asset-specific impact, reachability, remediation, or a security verdict.

## Source sample and integration

- [`kev-latest-sample.json`](kev-latest-sample.json) — timestamped CISA snapshot, not a live Vyonetix API response.
- [`epss-kev-live-sample.json`](epss-kev-live-sample.json) — captured response from the primary Worker; source observation timestamps are embedded.
- [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals)
- [GitHub Action guide](integrations/github-action/README.md) — early access, requires the caller’s own RapidAPI key, and sends supported package coordinates to RapidAPI/OSV.
