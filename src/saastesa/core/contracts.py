from enum import StrEnum
from typing import Any, Literal, TypeAlias


class FindingStandard(StrEnum):
    OCSF = "OCSF"


FindingSchemaVersion: TypeAlias = Literal["1.1.0"]
CURRENT_FINDING_SCHEMA_VERSION: FindingSchemaVersion = "1.1.0"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class FindingSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingDomain(StrEnum):
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    IDENTITY = "identity"
    CLOUD = "cloud"
    CONTAINER = "container"
    OTHER = "other"


class FindingClass(StrEnum):
    SECURITY_FINDING = "Security Finding"


class FindingActivity(StrEnum):
    CREATE = "Create"


class FindingReferenceType(StrEnum):
    CVE = "cve"
    CWE = "cwe"
    OWASP = "owasp"
    MITRE_ATTACK = "mitre_attack"


JSONValue: TypeAlias = Any
