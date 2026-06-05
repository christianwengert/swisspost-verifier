from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CheckResult:
    check_id: str
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerificationReport:
    phase: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def add(self, check_id: str, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(CheckResult(check_id, name, ok, detail))

    def failing(self) -> list[CheckResult]:
        return [check for check in self.checks if not check.ok]
