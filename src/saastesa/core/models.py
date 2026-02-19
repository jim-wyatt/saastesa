from dataclasses import dataclass
from datetime import datetime

from saastesa.core.contracts import (
    FindingActivity,
    FindingClass,
    FindingDomain,
    FindingSchemaVersion,
    FindingSeverity,
    FindingStandard,
    FindingStatus,
    JSONValue,
)


@dataclass(frozen=True)
class ThreatSignal:
    source: str
    signal_type: str
    severity: int
    detected_at: datetime
    metadata: dict[str, JSONValue]


@dataclass(frozen=True)
class FindingResource:
    uid: str
    name: str
    type: str
    platform: str


@dataclass(frozen=True)
class FindingReferences:
    cve: tuple[str, ...]
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    mitre_attack: tuple[str, ...]


@dataclass(frozen=True)
class SecurityFinding:
    finding_uid: str
    standard: FindingStandard
    schema_version: FindingSchemaVersion
    status: FindingStatus
    severity_id: int
    severity: FindingSeverity
    risk_score: int
    title: str
    description: str
    category_name: str
    class_name: FindingClass
    type_name: str
    domain: FindingDomain
    activity_name: FindingActivity
    time: datetime
    source: str
    resource: FindingResource
    references: FindingReferences
    raw_data: dict[str, JSONValue]
