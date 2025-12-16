# validator/policy_enforcer.py

import os
from typing import Dict, Any, Tuple, List
from dataclasses import dataclass

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


# =====================================================================
# RESULT CONTAINER
# =====================================================================

@dataclass
class PolicyCheckResult:
    rule: str
    id: str
    severity: str
    status: str
    message: str
    category: str
    description: str
    reason: str
    details: Any = None

    def __post_init__(self):
        # Normalize text fields to avoid None values
        self.rule = str(self.rule)
        self.id = str(self.id)
        self.severity = str(self.severity)
        self.status = str(self.status)
        self.message = str(self.message)
        self.category = str(self.category)
        self.description = str(self.description)
        self.reason = str(self.reason)


# =====================================================================
# POLICY ENFORCER
# =====================================================================

class PolicyEnforcer:

    def __init__(self, policy_path: str | None = None):
        self.policy_path = policy_path or DEFAULT_POLICY_PATH
        self.policy = self._load_policy()

    # -----------------------------------------------------------------
    def _load_policy(self) -> Dict[str, Any]:
        """
        Loads YAML policy file and normalizes structure.
        """
        if not os.path.exists(self.policy_path):
            return {"policies": {}}

        if yaml is None:
            raise RuntimeError("pyyaml not installed. Run: pip install pyyaml")

        with open(self.policy_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        policies = raw.get("policies", {})

        # Support old formats: list → dict
        if isinstance(policies, list):
            normalized = {}
            for item in policies:
                if isinstance(item, dict):
                    for k, v in item.items():
                        normalized[k] = v
            return {"policies": normalized}

        if not isinstance(policies, dict):
            return {"policies": {}}

        return {"policies": policies}

    # -----------------------------------------------------------------
    def enforce(self, detection_result, parsed_bom, filename=None):
        """
        Run semantic checks + apply policy rules.

        - Missing policy entries = SKIP (as per your request)
        - strict=true + failed → FAIL
        - severity=warning → WARN
        - severity=off → SKIP
        """
        semantic_results = run_semantic_checks(
            parsed_bom,
            detection_result.format,
            detection_result.bom_type,
            detection_result.spec_version
        )

        policy_cfg = self.policy.get("policies", {})
        results: List[PolicyCheckResult] = []
        overall_ok = True

        for check_name, check_info in semantic_results.items():

            # =======================================================
            # 1. Load rule from policy.yaml
            # =======================================================
            cfg = policy_cfg.get(check_name)

            # Rule not defined → AUTO-SKIP (optional behavior)
            if cfg is None:
                results.append(
                    PolicyCheckResult(
                        rule=check_name,
                        id=check_name.upper(),
                        severity="off",
                        status="SKIP",
                        message=f"Rule '{check_name}' not defined in policy. Skipped.",
                        category="undefined",
                        description="",
                        reason="Rule not present in policy configuration.",
                        details=None
                    )
                )
                continue

            # =======================================================
            # 2. Extract policy rule properties
            # =======================================================
            severity = cfg.get("severity", "off")          # error / warning / off
            strict = cfg.get("strict", False)
            rule_id = cfg.get("id", check_name.upper())
            display_name = cfg.get("display_name", check_name)
            category = cfg.get("category", "general")
            description = cfg.get("description", "")
            reason = cfg.get("reason", "")

            passed = check_info.get("passed", False)
            message = check_info.get("message", "")
            details = check_info.get("details", None)

            # =======================================================
            # 3. Detemine status
            # =======================================================
            if severity == "off":
                status = "SKIP"

            elif passed:
                status = "PASS"

            else:
                if severity == "warning":
                    status = "WARN"
                else:
                    status = "FAIL"

            # =======================================================
            # 4. Affect overall validation result
            # =======================================================
            if status == "FAIL":
                overall_ok = False

            # =======================================================
            # 5. Store the result
            # =======================================================
            results.append(
                PolicyCheckResult(
                    rule=display_name,
                    id=rule_id,
                    severity=severity,
                    status=status,
                    message=message,
                    category=category,
                    description=description,
                    reason=reason,
                    details=details
                )
            )

        return overall_ok, results
