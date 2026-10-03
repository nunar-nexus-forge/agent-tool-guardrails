# SPDX-License-Identifier: Apache-2.0
"""Trust-scored governance.

* compliance score ``C_i(t) = (1/K) Σ Ω_i(a_k, P)`` over a window of the agent's last ``K``
  actions, where ``Ω`` is 1 when the action was allowed by policy and 0 otherwise (slots
  not yet used count as compliant, so a new agent starts at 1.0);
* trust ``T_i(t+1) = λ·T_i(t) + (1 − λ)·E_i(t)`` from behavioural evidence;
* pairwise trust ``T_ij(t+Δt) = γ·T_ij(t) + (1 − γ)·ψ_ij(t)`` and privilege weights
  ``φ_ij = T_ij / Σ_k T_ik``;
* fusion ``G_i(t) = α·C_i(t) + (1 − α)·T_i(t)``; agents whose fusion score falls below the
  thresholds are throttled or isolated by the engine;
* policy adaptation ``P(t+Δt) = P(t) + λ·ΔR(t)`` exposed as a *strictness* knob that
  predicates can read as ``env.strictness``.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GovernanceConfig:
    lam: float = 0.8
    gamma: float = 0.8
    alpha: float = 0.5
    window: int = 20
    initial_trust: float = 0.7
    throttle_below: float = 0.6
    isolate_below: float = 0.4
    adapt_sensitivity: float = 0.1

    def __post_init__(self) -> None:
        for name in ("lam", "gamma", "alpha", "initial_trust", "throttle_below", "isolate_below"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")
        if self.isolate_below > self.throttle_below:
            raise ValueError("isolate_below must not exceed throttle_below")


class ComplianceTracker:
    def __init__(self, window: int = 20) -> None:
        self.window = max(1, window)
        self._history: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=self.window))
        self.violations: dict[str, int] = defaultdict(int)

    def record(self, agent: str, allowed: bool) -> float:
        self._history[agent].append(1 if allowed else 0)
        if not allowed:
            self.violations[agent] += 1
        return self.score(agent)

    def score(self, agent: str) -> float:
        hist = self._history.get(agent)
        if not hist:
            return 1.0
        violations = sum(1 for v in hist if v == 0)
        return (self.window - violations) / self.window

    def actions(self, agent: str) -> int:
        return len(self._history.get(agent, ()))


class TrustModel:
    def __init__(self, config: GovernanceConfig | None = None) -> None:
        self.config = config or GovernanceConfig()
        self.trust: dict[str, float] = {}
        self.pairwise: dict[tuple[str, str], float] = {}

    def get(self, agent: str) -> float:
        return self.trust.get(agent, self.config.initial_trust)

    def set(self, agent: str, value: float) -> None:
        self.trust[agent] = min(1.0, max(0.0, value))

    def update(self, agent: str, evidence_score: float) -> float:
        lam = self.config.lam
        new = lam * self.get(agent) + (1.0 - lam) * min(1.0, max(0.0, evidence_score))
        self.trust[agent] = new
        return new

    def get_pair(self, i: str, j: str) -> float:
        return self.pairwise.get((i, j), self.config.initial_trust)

    def update_pair(self, i: str, j: str, collaboration_score: float) -> float:
        g = self.config.gamma
        new = g * self.get_pair(i, j) + (1.0 - g) * min(1.0, max(0.0, collaboration_score))
        self.pairwise[(i, j)] = new
        return new

    def privilege_weights(self, i: str) -> dict[str, float]:
        peers = {j: t for (a, j), t in self.pairwise.items() if a == i}
        total = sum(peers.values())
        return {j: (t / total if total else 0.0) for j, t in peers.items()}

    def fusion(self, agent: str, compliance: float, alpha: float | None = None) -> float:
        a = self.config.alpha if alpha is None else alpha
        return a * compliance + (1.0 - a) * self.get(agent)


@dataclass
class GovernanceState:
    agent: str
    compliance: float
    trust: float
    fusion: float
    level: str  # normal | throttle | isolate
    actions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "compliance": round(self.compliance, 4),
            "trust": round(self.trust, 4),
            "fusion": round(self.fusion, 4),
            "level": self.level,
            "actions": self.actions,
        }


@dataclass
class GovernanceLoop:
    """The continuous monitor -> assess -> adapt -> enforce loop."""

    config: GovernanceConfig = field(default_factory=GovernanceConfig)
    trust: TrustModel = field(default=None)  # type: ignore[assignment]
    compliance: ComplianceTracker = field(default=None)  # type: ignore[assignment]
    strictness: float = 0.0
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.trust is None:
            self.trust = TrustModel(self.config)
        if self.compliance is None:
            self.compliance = ComplianceTracker(self.config.window)

    def record_decision(self, agent: str, allowed: bool) -> GovernanceState:
        """Feed one policy decision: updates compliance and trust, returns the new state."""
        self.compliance.record(agent, allowed)
        self.trust.update(agent, 1.0 if allowed else 0.0)
        return self.state(agent)

    def evidence(self, agent: str, score: float) -> float:
        """External behavioural evidence (decision consistency, cooperative contribution, ...)."""
        return self.trust.update(agent, score)

    def level(self, agent: str) -> str:
        if not self.enabled:
            return "normal"
        g = self.trust.fusion(agent, self.compliance.score(agent))
        if g < self.config.isolate_below:
            return "isolate"
        if g < self.config.throttle_below:
            return "throttle"
        return "normal"

    def state(self, agent: str) -> GovernanceState:
        c = self.compliance.score(agent)
        t = self.trust.get(agent)
        return GovernanceState(
            agent, c, t, self.trust.fusion(agent, c), self.level(agent), self.compliance.actions(agent)
        )

    def adapt(self, delta_risk: float) -> float:
        """``P(t+Δt) = P(t) + λ·ΔR(t)`` - move the strictness knob by the observed risk change."""
        self.strictness = min(1.0, max(0.0, self.strictness + self.config.adapt_sensitivity * delta_risk))
        return self.strictness

    def reset(self, agent: str) -> None:
        self.trust.set(agent, self.config.initial_trust)
        self.compliance._history.pop(agent, None)

    def snapshot(self) -> dict[str, Any]:
        agents = set(self.trust.trust) | set(self.compliance._history)
        return {"strictness": self.strictness, "agents": {a: self.state(a).to_dict() for a in sorted(agents)}}
