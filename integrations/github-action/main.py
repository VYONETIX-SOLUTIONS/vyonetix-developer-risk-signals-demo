#!/usr/bin/env python3
"""Submit a bounded CycloneDX package inventory to the Vyonetix RapidAPI gateway."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}
MAX_PACKAGES = 50
MAX_RESPONSE_BYTES = 2_000_000
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+p\.rapidapi\.com$", re.I)


class ActionError(Exception):
    pass


def parse_purl(value: Any) -> tuple[str, str, str] | None:
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return None
    body = value[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None
    purl_type, path_version = body.split("/", 1)
    if "@" not in path_version:
        return None
    encoded_path, encoded_version = path_version.rsplit("@", 1)
    ecosystem = ECOSYSTEMS.get(purl_type.lower())
    package_name = urllib.parse.unquote(encoded_path)
    version = urllib.parse.unquote(encoded_version)
    if purl_type.lower() == "maven" and "/" in package_name:
        group, artifact = package_name.rsplit("/", 1)
        package_name = group + ":" + artifact
    if not ecosystem or not package_name or not version:
        return None
    if any(ord(ch) < 32 for ch in package_name + version):
        return None
    if len(package_name) > 160 or len(version) > 160:
        return None
    return ecosystem, package_name, version


def load_packages(sbom_path: Path) -> tuple[list[dict[str, str]], int]:
    try:
        with sbom_path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActionError("Cannot read the CycloneDX JSON SBOM at the configured path.") from exc
    if not isinstance(document, dict) or not isinstance(document.get("components"), list):
        raise ActionError("The file must be a CycloneDX JSON SBOM with a components array.")

    packages: dict[tuple[str, str, str], None] = {}
    skipped = 0
    for component in document["components"]:
        parsed = parse_purl(component.get("purl") if isinstance(component, dict) else None)
        if parsed is None:
            skipped += 1
            continue
        packages[parsed] = None
    ordered = sorted(packages)
    if not ordered:
        raise ActionError("No supported package URLs with explicit versions were found in the SBOM.")
    if len(ordered) > MAX_PACKAGES:
        raise ActionError(
            f"The SBOM contains {len(ordered)} supported unique packages; one API request accepts at most {MAX_PACKAGES}. "
            "Reduce the SBOM scope before running this action so API usage stays predictable."
        )
    return ([{"ecosystem": e, "name": n, "version": v} for e, n, v in ordered], skipped)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call_api(host: str, key: str, path: str, packages: list[dict[str, str]]) -> dict[str, Any]:
    normalized_host = host.strip().lower()
    if not HOST_RE.fullmatch(normalized_host):
        raise ActionError("RAPIDAPI_HOST must be the API's *.p.rapidapi.com hostname from its listing.")
    if not key.strip():
        raise ActionError("RAPIDAPI_KEY is empty; store the consumer key in a repository secret.")
    body = json.dumps({"packages": packages}, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"https://{normalized_host}{path}",
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-RapidAPI-Key": key.strip(),
            "X-RapidAPI-Host": normalized_host,
        },
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=25) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ActionError("The API response exceeded the action's 2 MB safety limit.")
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise ActionError(f"RapidAPI returned HTTP {status}; verify the API host, key, plan quota and live listing.") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ActionError("RapidAPI could not be reached over HTTPS; check the network and API listing status.") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ActionError("RapidAPI returned a response that was not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict) or payload.get("status") != "success" or not isinstance(payload.get("data"), list):
        raise ActionError("RapidAPI returned an unexpected response envelope; see the listing's current response schema.")
    return payload


def count_dependency_results(payload: dict[str, Any]) -> tuple[int, int]:
    rows = payload["data"]
    package_hits = 0
    finding_count = 0
    for row in rows:
        findings = row.get("findings", []) if isinstance(row, dict) else []
        if isinstance(findings, list):
            finding_count += len(findings)
            package_hits += bool(findings)
    return int(package_hits), finding_count


def count_malicious_results(payload: dict[str, Any]) -> int:
    return sum(
        1
        for row in payload["data"]
        if isinstance(row, dict) and row.get("source_reported_malicious") is True
    )


def write_outputs(values: dict[str, int]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as output:
            for key, value in values.items():
                output.write(f"{key}={value}\n")


def write_summary(package_count: int, skipped: int, package_hits: int, findings: int, malicious_hits: int | None) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        "## Vyonetix Developer Risk Signals",
        "",
        f"- Supported package/version tuples checked: **{package_count}**",
        f"- Package tuples with OSV advisory matches: **{package_hits}**",
        f"- Advisory identifiers returned: **{findings}**",
    ]
    if malicious_hits is not None:
        lines.append(f"- Packages with exact OpenSSF MAL report matches: **{malicious_hits}**")
    if skipped:
        lines.append(f"- Unsupported or unversioned CycloneDX components skipped: **{skipped}**")
    lines += ["", "Results contain source-linked evidence identifiers. Review each source record before making package decisions."]
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


def self_check() -> int:
    cases = {
        "pkg:npm/%40scope/pkg@1.2.3": ("npm", "@scope/pkg", "1.2.3"),
        "pkg:pypi/Requests@2.32.0": ("PyPI", "Requests", "2.32.0"),
        "pkg:golang/github.com/example/mod@v1.0.0": ("Go", "github.com/example/mod", "v1.0.0"),
        "pkg:maven/org.example/library@4.2.0": ("Maven", "org.example:library", "4.2.0"),
        "pkg:cargo/serde@1.0.0": ("crates.io", "serde", "1.0.0"),
    }
    for value, expected in cases.items():
        if parse_purl(value) != expected:
            raise ActionError("CycloneDX package URL parser self-check failed.")
    if parse_purl("pkg:npm/lodash") is not None or parse_purl("pkg:unknown/pkg@1") is not None:
        raise ActionError("Unsupported/missing-version package URL self-check failed.")
    print("Self-check passed: supported package URL formats and rejection cases.")
    return 0


def main() -> int:
    if "--self-check" in sys.argv[1:]:
        return self_check()
    try:
        sbom_value = os.environ.get("SBOM_PATH", "").strip()
        if not sbom_value:
            raise ActionError("SBOM_PATH is required.")
        sbom_path = Path(sbom_value).expanduser()
        packages, skipped = load_packages(sbom_path)
        host = os.environ.get("RAPIDAPI_HOST", "")
        key = os.environ.get("RAPIDAPI_KEY", "")
        dependency_payload = call_api(host, key, "/v1/dependencies/check", packages)
        package_hits, findings = count_dependency_results(dependency_payload)
        malicious_hits: int | None = None
        if os.environ.get("CHECK_MALICIOUS", "false").strip().lower() == "true":
            malicious_payload = call_api(host, key, "/v1/packages/malicious-check", packages)
            malicious_hits = count_malicious_results(malicious_payload)
        output = {
            "package_count": len(packages),
            "advisory_package_count": package_hits,
            "advisory_count": findings,
            "malicious_package_count": malicious_hits or 0,
        }
        write_outputs(output)
        write_summary(len(packages), skipped, package_hits, findings, malicious_hits)
        print(
            f"Checked {len(packages)} supported package/version tuples; "
            f"{package_hits} had OSV matches ({findings} identifiers)."
        )
        if malicious_hits is not None:
            print(f"Exact OpenSSF MAL report matches: {malicious_hits} package tuple(s).")
        if skipped:
            print(f"Skipped {skipped} unsupported or unversioned component(s).")
        fail_on_findings = os.environ.get("FAIL_ON_FINDINGS", "false").strip().lower() == "true"
        if fail_on_findings and (findings > 0 or bool(malicious_hits)):
            print("Configured to fail on source matches; inspect the linked source records before changing dependencies.")
            return 1
        return 0
    except ActionError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
