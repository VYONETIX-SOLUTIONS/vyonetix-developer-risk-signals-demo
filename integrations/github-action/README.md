# GitHub Action integration

This local composite Action submits up to 50 unique, versioned components from a CycloneDX JSON SBOM to the Vyonetix Developer Risk Signals RapidAPI listing. It writes aggregate counts to the GitHub job summary and never prints package names, key material, or complete API responses.

## Release state

This is an early-access community integration published at [`integrations/github-action`](https://github.com/sudheer-vyo/vyonetix-developer-risk-signals-demo/tree/main/integrations/github-action). Its parser compiles and the local self-check passes. The three API routes passed authenticated RapidAPI gateway checks from the owner workspace; an independent consumer signup, metering check, and CI run have not been verified. This is a source release, not a GitHub Marketplace listing or a production security product.

The public listing combines a 100-request Basic tier with paid tiers, so RapidAPI currently requires a payment card for Basic. Read the current plan, quota, privacy, and bandwidth terms on the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals) before subscribing. No consumer should assume a free subscription is card-free.

## Caller requirements

- Generate a CycloneDX JSON SBOM in the caller's workflow and store it at a path available to the job.
- Configure the API hostname from the RapidAPI listing as a repository variable named `VYONETIX_RAPIDAPI_HOST`.
- Store a consumer key from the caller's own RapidAPI subscription as a repository secret named `VYONETIX_RAPIDAPI_KEY`.
- The Worker receives only ecosystem/name/version tuples, up to 50 per run. Package names and versions are transmitted to RapidAPI and OSV. Do not use this Action for private package identifiers or confidential inventory.
- The default run makes one API call. Setting `check-malicious: "true"` makes a second call. GitHub schedule intervals and API quotas are not real-time guarantees.
- A finding is evidence for review, not an automatic claim that a dependency is exploitable, malicious, or unsafe. `fail-on-findings` defaults to false.

## Example workflow

The published example uses the subdirectory Action directly. Replace the host value with the `*.p.rapidapi.com` host shown on the listing and add your own RapidAPI consumer key as a repository secret. The key remains with GitHub Actions and is never placed in the workflow file:

```yaml
name: Dependency evidence
on:
  push:
    paths:
      - "bom.json"
      - "**/bom.json"
  workflow_dispatch:
  schedule:
    - cron: "23 8 * * 1-5"

permissions:
  contents: read

jobs:
  risk-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sudheer-vyo/vyonetix-developer-risk-signals-demo/integrations/github-action@main
        with:
          sbom-path: bom.json
          rapidapi-host: ${{ vars.VYONETIX_RAPIDAPI_HOST }}
          rapidapi-key: ${{ secrets.VYONETIX_RAPIDAPI_KEY }}
          check-malicious: "true"
          fail-on-findings: "false"
```

GitHub's scheduled workflows run only from the default branch and may be delayed or dropped during high load. Use `workflow_dispatch` for an immediate manual run and a push trigger for changes to the SBOM. See [GitHub schedule event behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

The workflow sends supported package names and versions to RapidAPI and OSV. Do not use it with confidential inventories, private package identifiers, or data you are not authorized to disclose. Its output reports source-record matches, not exploitability or a safety verdict; keep `fail-on-findings` false until you have reviewed how your organization wants to handle results.

## Local parser check

From this directory:

```powershell
py -3.12 -m py_compile .\main.py
py -3.12 .\main.py --self-check
```

The self-check uses synthetic package URLs and does not contact RapidAPI or disclose a key.
