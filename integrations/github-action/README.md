# VYONETIX SOLUTIONS Dependency Evidence Action

Use Vyonetix Developer Risk Signals from a GitHub Actions workflow that already produces a CycloneDX JSON SBOM.

**[API listing and plans](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals)** · **[API examples](https://github.com/sudheer-vyo/vyonetix-developer-risk-signals-demo/blob/main/samples/quickstart.md)**

This early-access integration sends up to 50 supported, versioned package coordinates to the API. It writes aggregate counts to the job summary. It is a source release, not a production security control or a GitHub Marketplace listing.

## What it checks

- OSV advisory identifiers for caller-supplied package versions.
- Optional exact OpenSSF `MAL-YYYY-NNNN` report matches.
- Aggregate match counts, without printing package names, API keys, or full upstream responses.

A match is evidence for human review. It does not say that a package is exploitable, malicious in your environment, or unsafe. A no-match is not a safety verdict.

## Quick setup

1. Generate a CycloneDX JSON SBOM in your workflow.
2. Copy the API hostname shown on the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals).
3. Add the host as a repository variable called `VYONETIX_RAPIDAPI_HOST`.
4. Subscribe to an available RapidAPI plan and save your consumer key as repository secret `VYONETIX_RAPIDAPI_KEY`.
5. Copy [example-workflow.yml](example-workflow.yml) and keep the reviewed commit pin.

```yaml
- uses: sudheer-vyo/vyonetix-developer-risk-signals-demo/integrations/github-action@c84b27fc86c794710dd4ded38678b34d7f67cacd
  with:
    sbom-path: bom.json
    rapidapi-host: ${{ vars.VYONETIX_RAPIDAPI_HOST }}
    rapidapi-key: ${{ secrets.VYONETIX_RAPIDAPI_KEY }}
    check-malicious: "true"
    fail-on-findings: "false"
```

## Data handling and privacy

- Only supported ecosystem, package name, and version tuples are sent; the Action does not upload the complete SBOM file.
- Package coordinates are transmitted to RapidAPI and OSV. Do not use the Action with confidential inventories or private package identifiers.
- The default run makes one API call. Enabling `check-malicious` makes a second call. Quotas and GitHub schedule timing apply; scheduled workflows are not real-time guarantees.
- `fail-on-findings` defaults to false. Review the returned source evidence before deciding how to handle a match.
- Keep the RapidAPI key in GitHub Actions Secrets. Never put it in workflow YAML, logs, or artifacts.

## Availability and verification

The three REST operations passed authenticated gateway checks on 12 November 2026. Local parser/self-checks passed. Independent customer signup, plan metering, and third-party CI use have not been verified. The service is a controlled pilot without an availability SLA.

Current quotas, payment-card requirements, terms, and plan availability are shown on the [RapidAPI listing](https://rapidapi.com/vyonetix-solutions-vyonetix-solutions-default/api/vyonetix-developer-risk-signals).
