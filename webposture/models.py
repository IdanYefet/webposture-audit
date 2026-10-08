from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Risk level of a finding, ordered from most to least serious."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security observation produced by one of the audit modules."""

    title: str
    severity: Severity
    description: str
    recommendation: str