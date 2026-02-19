from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

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


class ThreatSignalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    signal_type: str
    severity: int = Field(ge=1, le=5)
    detected_at: datetime
    metadata: dict[str, JSONValue] = Field(default_factory=dict)


class FindingResourceOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uid: str
    name: str
    type: str
    platform: str


class FindingReferencesOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)


class SecurityFindingOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    resource: FindingResourceOut
    references: FindingReferencesOut
    raw_data: dict[str, JSONValue]


class IngestSignalsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signals: list[ThreatSignalIn]


class IngestSignalsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ingested: int
    findings: list[SecurityFindingOut]


class IngestFindingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[SecurityFindingOut]


class IngestFindingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ingested: int


class FindingsSummaryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    low: int
    medium: int
    high: int
    critical: int
