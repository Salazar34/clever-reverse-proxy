"""
SecLab DoS Mitigation - High-Performance Computational Cost Engine
Module: proxy.cost_engine

Computes the estimated computational complexity C(R) of an incoming HTTP request
in memory without database interaction, achieving sub-50 microsecond execution times.
"""

from __future__ import annotations

import logging
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

logger = logging.getLogger("proxy.cost_engine")

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "cost_rules.yaml"


@dataclass(slots=True, frozen=True)
class ParameterRule:
    """Compiled parameter cost rule."""
    name: str
    rule_type: str  # 'linear' | 'presence_penalty' | 'categorical'
    weight: float = 0.0
    default_val: Any = None
    category_weights: dict[str, float] = field(default_factory=dict)

    def evaluate(self, raw_value: Any) -> float:
        if self.rule_type == "linear":
            val = raw_value if raw_value is not None else self.default_val
            try:
                numeric = float(val) if val is not None else 0.0
                return self.weight * max(0.0, numeric) if math.isfinite(numeric) else 0.0
            except (ValueError, TypeError):
                return 0.0

        elif self.rule_type == "presence_penalty":
            if raw_value is not None and str(raw_value).strip() != "":
                return self.weight
            return 0.0

        elif self.rule_type == "categorical":
            val = str(raw_value).strip().lower() if raw_value is not None else str(self.default_val).strip().lower()
            return self.category_weights.get(val, self.category_weights.get(str(self.default_val).strip().lower(), 0.0))

        return 0.0


@dataclass(slots=True)
class CompiledRoute:
    """Pre-compiled route definition for microsecond pattern matching."""
    name: str
    pattern: re.Pattern[str]
    methods: frozenset[str]
    base_cost: float
    parameter_rules: dict[str, ParameterRule]


class CostEngine:
    """
    Parametric in-memory cost estimation engine.
    
    Attributes:
        max_allowed_cost: Hard upper bound (C_max). Queries exceeding this are rejected.
        default_unmatched_cost: Default cost assigned to unmatched routes.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path or os.getenv("COST_RULES_PATH", DEFAULT_CONFIG_PATH))
        self.max_allowed_cost: float = 100.0
        self.default_unmatched_cost: float = 5.0
        self.routes: list[CompiledRoute] = []
        self._load_and_compile()

    def _load_and_compile(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Cost configuration file not found at: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            raw_cfg = yaml.safe_load(f) or {}

        self.max_allowed_cost = float(raw_cfg.get("max_allowed_cost", 100.0))
        self.default_unmatched_cost = float(raw_cfg.get("default_unmatched_cost", 5.0))

        compiled_routes = []
        for r in raw_cfg.get("routes", []):
            name = str(r.get("name", "unnamed_route"))
            path_pattern = str(r.get("path_pattern", ""))
            methods = frozenset(m.upper() for m in r.get("methods", ["GET"]))
            base_cost = float(r.get("base_cost", 1.0))

            param_rules: dict[str, ParameterRule] = {}
            for param_name, rule_def in (r.get("parameter_rules") or {}).items():
                rtype = rule_def.get("type")
                weight = float(rule_def.get("weight", 0.0))
                default_val = rule_def.get("default", None)
                cat_weights = {
                    str(k).lower(): float(v) for k, v in (rule_def.get("weights") or {}).items()
                }
                param_rules[param_name] = ParameterRule(
                    name=param_name,
                    rule_type=rtype,
                    weight=weight,
                    default_val=default_val,
                    category_weights=cat_weights,
                )

            compiled_routes.append(
                CompiledRoute(
                    name=name,
                    pattern=re.compile(path_pattern),
                    methods=methods,
                    base_cost=base_cost,
                    parameter_rules=param_rules,
                )
            )

        self.routes = compiled_routes
        logger.info(
            "CostEngine initialized: %d routes compiled from '%s' (C_max=%.1f)",
            len(self.routes),
            self.config_path,
            self.max_allowed_cost,
        )

    def estimate_cost(
        self,
        path: str,
        method: str = "GET",
        query_params: Mapping[str, Any] | None = None,
    ) -> float:
        """
        Estimates computational cost C(R) for a given HTTP request.
        
        Args:
            path: Absolute URL path (e.g. '/api/v1/orders').
            method: HTTP method (e.g. 'GET').
            query_params: Dictionary of parsed query string parameters.

        Returns:
            A float representing the estimated computational cost, clamped to max_allowed_cost.
        """
        method_upper = method.upper()
        matched_route: CompiledRoute | None = None

        # 1. High-speed regex path matching (< 2-5 us)
        for route in self.routes:
            if method_upper in route.methods and route.pattern.match(path):
                matched_route = route
                break

        # 2. Fallback for unmatched routes
        if matched_route is None:
            return min(self.default_unmatched_cost, self.max_allowed_cost)

        # 3. Summation of base cost and parametric rules
        total_cost = matched_route.base_cost
        params = query_params or {}

        for param_name, rule in matched_route.parameter_rules.items():
            val = params.get(param_name)
            total_cost += rule.evaluate(val)

        # 4. Normalization and clamping to upper ceiling C_max
        return min(round(total_cost, 4), self.max_allowed_cost)
