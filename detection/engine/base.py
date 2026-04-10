from __future__ import annotations
from abc import ABC, abstractmethod
from proxy.models import NormalizedRequest
from .types import RuleContext, RuleResult

class DetectionRule(ABC):
    id: str
    pack: str

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def supports(self, req: NormalizedRequest) -> bool:
        return True

    @abstractmethod
    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        raise NotImplementedError
