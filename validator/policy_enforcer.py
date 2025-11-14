# validator/policy_enforcer.py

import os
from typing import Dict, Any, Tuple, List
from dataclasses import dataclass
import json

try:
    import yaml
except ImportError:
    yaml = None

from validator.semantic_validator import run_semantic_checks


DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(__file__),
    "policies",
    "policy.yaml"
)


@dataclass
class PolicyCheckResult:
    rule: str
    id: str
    severity: str
    status: str
    message: str
    details: Any = None

    def __post_init__(self):
        self.rule = str(self.rule)
        self.id = str(self.id)
        self.severity = str(self.severity)
        self.status = str(self.status)
        self.message = str(self.message)


class PolicyEnforcer:
    def __init__(self, policy_path: str | None = None):
        self.policy_path = policy_path or DEFAULT_POLICY_PATH
        self.policy = self._load_policy()

    # -------------------------------------------------------------
    def _load_policy(self) -> Dict[str, Any]:
        if not os.path.exists(self.policy_path):
            return {"policies": {}}

        if yaml is None:
            raise RuntimeError("pyyaml not installed. Run: pip install pyyaml")

        with open(self.policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw = data.get("policies", {})

        # FIX: Normalize list -> dict
        if isinstance(raw, list):
            normalized = {}
            for item in raw:
                if isinstance(item, dict):
                    for k, v in item.items():
                        normalized[k] = v
            return {"policies": normalized}

        if not isinstance(raw, dict):
            return {"policies": {}}

        return {"policies": raw}

    # -------------------------------------------------------------
    def enforce(self, detection_result, parsed_bom, filename=None):

        checks = run_semantic_checks(
            parsed_bom,
            detection_result.format,
            detection_result.bom_type,
            detection_result.spec_version
        )

        policy_cfg = self.policy.get("policies", {})
        results: List[PolicyCheckResult] = []
        overall_ok = True

        for check_name, check_info in checks.items():

            cfg = policy_cfg.get(check_name, {})

            # support simple format:
            # require_purl: "error"
            if isinstance(cfg, str):
                severity = cfg
                rule_id = check_name.upper()
            else:
                severity = cfg.get("severity", "off")
                rule_id = cfg.get("id", check_name.upper())

            passed = check_info.get("passed", False)
            message = check_info.get("message", "")
            details = check_info.get("details", None)

            if severity == "off":
                status = "SKIP"
            elif passed:
                status = "PASS"
            else:
                status = "WARN" if severity == "warning" else "FAIL"

            if status == "FAIL":
                overall_ok = False

            results.append(
                PolicyCheckResult(
                    rule=check_name,
                    id=rule_id,
                    severity=severity,
                    status=status,
                    message=message,
                    details=details
                )
            )

        return overall_ok, results
