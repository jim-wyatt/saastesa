from collections.abc import Iterable
from datetime import datetime
from threading import Lock
from typing import cast

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, selectinload

from saastesa.api.db_models import (
    Base,
    FindingReferenceItemRecord,
    FindingResourceRecord,
    SecurityFindingRecord,
)
from saastesa.api.migrations import migrate_schema
from saastesa.core.contracts import (
    CURRENT_FINDING_SCHEMA_VERSION,
    FindingReferenceType,
    FindingSchemaVersion,
    JSONValue,
)
from saastesa.core.models import FindingReferences, FindingResource, SecurityFinding
from saastesa.core.risk_scoring import summarize_scores


class InMemoryFindingStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._findings: list[SecurityFinding] = []

    def add(self, findings: list[SecurityFinding]) -> None:
        with self._lock:
            self._findings.extend(findings)

    def list(self, limit: int = 100) -> list[SecurityFinding]:
        with self._lock:
            if limit <= 0:
                return []
            return self._findings[-limit:]

    def summary(self) -> dict[str, int]:
        with self._lock:
            return summarize_scores(self._findings)


class SQLAlchemyFindingStore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def init(self) -> None:
        migrate_schema(self.engine)

    def add(self, findings: list[SecurityFinding]) -> None:
        if not findings:
            return

        with Session(self.engine) as session:
            for finding in findings:
                resource = self._get_or_create_resource(session, finding.resource)
                existing = session.scalar(
                    select(SecurityFindingRecord).where(SecurityFindingRecord.finding_uid == finding.finding_uid)
                )
                if existing is None:
                    record = self._to_record(finding, resource)
                    self._set_reference_items(record, finding.references)
                    session.add(record)
                else:
                    self._update_record(existing, finding, resource)
            session.commit()

    def list(self, limit: int = 100) -> list[SecurityFinding]:
        if limit <= 0:
            return []

        with Session(self.engine) as session:
            rows = session.scalars(
                select(SecurityFindingRecord)
                .options(
                    selectinload(SecurityFindingRecord.resource),
                    selectinload(SecurityFindingRecord.reference_items),
                )
                .order_by(SecurityFindingRecord.time.desc(), SecurityFindingRecord.id.desc())
                .limit(limit)
            ).all()

        findings = [self._from_record(row) for row in rows]
        findings.reverse()
        return findings

    def summary(self) -> dict[str, int]:
        return summarize_scores(self.list(limit=100000))

    def _to_record(
        self, finding: SecurityFinding, resource: FindingResourceRecord
    ) -> SecurityFindingRecord:
        return SecurityFindingRecord(
            finding_uid=finding.finding_uid,
            standard=finding.standard,
            schema_version=finding.schema_version,
            status=finding.status,
            severity_id=finding.severity_id,
            severity=finding.severity,
            risk_score=finding.risk_score,
            title=finding.title,
            description=finding.description,
            category_name=finding.category_name,
            class_name=finding.class_name,
            type_name=finding.type_name,
            domain=finding.domain,
            activity_name=finding.activity_name,
            time=finding.time,
            source=finding.source,
            resource=resource,
            raw_data=cast(dict[str, object], finding.raw_data),
        )

    def _update_record(
        self,
        record: SecurityFindingRecord,
        finding: SecurityFinding,
        resource: FindingResourceRecord,
    ) -> None:
        record.standard = finding.standard
        record.schema_version = finding.schema_version
        record.status = finding.status
        record.severity_id = finding.severity_id
        record.severity = finding.severity
        record.risk_score = finding.risk_score
        record.title = finding.title
        record.description = finding.description
        record.category_name = finding.category_name
        record.class_name = finding.class_name
        record.type_name = finding.type_name
        record.domain = finding.domain
        record.activity_name = finding.activity_name
        record.time = finding.time
        record.source = finding.source
        record.resource = resource
        self._set_reference_items(record, finding.references)
        record.raw_data = cast(dict[str, object], finding.raw_data)

    def _from_record(self, record: SecurityFindingRecord) -> SecurityFinding:
        references_by_type: dict[FindingReferenceType, list[str]] = {
            FindingReferenceType.CVE: [],
            FindingReferenceType.CWE: [],
            FindingReferenceType.OWASP: [],
            FindingReferenceType.MITRE_ATTACK: [],
        }
        for item in record.reference_items:
            references_by_type[item.reference_type].append(item.reference_value)

        resource = record.resource
        return SecurityFinding(
            finding_uid=record.finding_uid,
            standard=record.standard,
            schema_version=cast(FindingSchemaVersion, CURRENT_FINDING_SCHEMA_VERSION),
            status=record.status,
            severity_id=record.severity_id,
            severity=record.severity,
            risk_score=record.risk_score,
            title=record.title,
            description=record.description,
            category_name=record.category_name,
            class_name=record.class_name,
            type_name=record.type_name,
            domain=record.domain,
            activity_name=record.activity_name,
            time=_ensure_datetime(record.time),
            source=record.source,
            resource=FindingResource(
                uid=resource.uid,
                name=resource.name,
                type=resource.type,
                platform=resource.platform,
            ),
            references=FindingReferences(
                cve=tuple(references_by_type[FindingReferenceType.CVE]),
                cwe=tuple(references_by_type[FindingReferenceType.CWE]),
                owasp=tuple(references_by_type[FindingReferenceType.OWASP]),
                mitre_attack=tuple(references_by_type[FindingReferenceType.MITRE_ATTACK]),
            ),
            raw_data=cast(dict[str, JSONValue], dict(record.raw_data or {})),
        )

    def _get_or_create_resource(
        self, session: Session, resource: FindingResource
    ) -> FindingResourceRecord:
        existing = session.scalar(
            select(FindingResourceRecord).where(
                FindingResourceRecord.uid == resource.uid,
                FindingResourceRecord.name == resource.name,
                FindingResourceRecord.type == resource.type,
                FindingResourceRecord.platform == resource.platform,
            )
        )
        if existing is not None:
            return existing

        created = FindingResourceRecord(
            uid=resource.uid,
            name=resource.name,
            type=resource.type,
            platform=resource.platform,
        )
        session.add(created)
        session.flush()
        return created

    def _set_reference_items(
        self, record: SecurityFindingRecord, references: FindingReferences
    ) -> None:
        items_by_type = {
            FindingReferenceType.CVE: references.cve,
            FindingReferenceType.CWE: references.cwe,
            FindingReferenceType.OWASP: references.owasp,
            FindingReferenceType.MITRE_ATTACK: references.mitre_attack,
        }
        record.reference_items = [
            FindingReferenceItemRecord(reference_type=reference_type, reference_value=value)
            for reference_type, values in items_by_type.items()
            for value in sorted(set(values))
        ]


def _ensure_datetime(value: datetime) -> datetime:
    return value
