# Vyonetix Dependency Evidence Check — early access

The company-owned action is a small CI entry point for the Vyonetix Developer Risk Signals API. It accepts a caller-generated CycloneDX JSON SBOM, extracts supported public ecosystem/name/version tuples, and requests advisory identifiers from OSV through the API. An optional second call checks exact OpenSSF `MAL-` report identifiers. It does not upload the full SBOM file.

The current RapidAPI product has four REST routes. This Action uses the two package-coordinate operations only; it does not call the CISA KEV catalog or the FIRST EPSS + KEV prioritization operation. The new CVE route can be called from a custom workflow using the [API quickstart](../../quickstart.md).

## Install and configure

Use the commit-pinned action reference in [`example-workflow.yml`](example-workflow.yml). Add a consumer-owned RapidAPI key to the repository as a secret named `RAPIDAPI_KEY`; do not hard-code it. The consumer must subscribe to a current plan in the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals).

Before use, read [`action.yml`](action.yml) and the example workflow. Package coordinates are sent to RapidAPI and OSV for matching. Do not use this integration with private package inventories, confidential SBOM metadata, customer secrets, or other sensitive names.

## Evidence and limits

The Action writes aggregate counts to the workflow summary. A matched source advisory or OpenSSF report is evidence for a human or caller-owned policy to review. A no-match is not a safety verdict. The API does not inspect source code, determine deployment exposure, or remediate a dependency.

This is an early-access integration. The Cloudflare `workers.dev` origin has no availability SLA.
