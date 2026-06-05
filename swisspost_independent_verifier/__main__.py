from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .dataset import FixtureDataset
from .signatures import TrustStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent verifier for Swiss Post e-voting evidence")
    parser.add_argument("phase", choices=["config", "tally"], help="verification phase to execute")
    parser.add_argument("dataset", type=Path, help="dataset directory or supported fixture bundle")
    parser.add_argument("--trust-store", type=Path, help="directory containing signer certificates named by signer id")
    parser.add_argument("--json", action="store_true", help="emit machine-readable report")
    args = parser.parse_args(argv)

    trust_store = TrustStore.from_directory(args.trust_store) if args.trust_store else None
    verifier = FixtureDataset(args.dataset, trust_store=trust_store)
    report = verifier.verify_config_phase() if args.phase == "config" else verifier.verify_tally()
    if args.json:
        print(json.dumps({"phase": report.phase, "ok": report.ok, "checks": [check.__dict__ for check in report.checks]}, indent=2))
    else:
        print(f"{report.phase}: {'OK' if report.ok else 'FAILED'}")
        for check in report.checks:
            detail = f" ({check.detail})" if check.detail else ""
            print(f"{check.check_id} {check.name}: {'OK' if check.ok else 'FAILED'}{detail}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
