"""Export scan results as SARIF 2.1.0 for GitHub Code Scanning."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from snapcheck import __version__
from snapcheck.recommendations import SecretRisk
from snapcheck.report import ScanReport

_LEVEL = {
    SecretRisk.CRITICAL: "error",
    SecretRisk.REVIEW: "warning",
    SecretRisk.PLACEHOLDER: "note",
    SecretRisk.FALSE_POSITIVE: "none",
}


def to_sarif(report: ScanReport) -> str:
    results = []
    for item in report.health.classified_secrets:
        if item.risk == SecretRisk.FALSE_POSITIVE:
            continue
        f = item.finding
        results.append(
            {
                "ruleId": f.kind.replace(" ", "_").lower(),
                "level": _LEVEL[item.risk],
                "message": {"text": f"Potential {f.kind} detected"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.path)},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
                "properties": {"risk": item.risk.value},
            }
        )

    for item in report.large_files:
        results.append(
            {
                "ruleId": "large_file",
                "level": "warning",
                "message": {"text": f"Large file: {item.size_bytes} bytes"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(item.path)},
                        }
                    }
                ],
            }
        )

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SnapCheck",
                        "version": __version__,
                        "informationUri": "https://github.com/midnight-bot/snapcheck",
                        "rules": [
                            {
                                "id": "generic_api_key",
                                "name": "Generic API Key",
                                "shortDescription": {"text": "Potential API key in source"},
                            },
                            {
                                "id": "large_file",
                                "name": "Large File",
                                "shortDescription": {"text": "File exceeds size threshold"},
                            },
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)