import json
from datetime import datetime
from typing import Any, cast

from sqlalchemy import Engine, inspect, text

from saastesa.api.db_models import (
    Base,
    FindingReferenceItemRecord,
    FindingResourceRecord,
    SecurityFindingRecord,
)
from saastesa.core.contracts import FindingReferenceType

_LEGACY_REFERENCE_COLUMN = "references_json"
_LEGACY_RESOURCE_COLUMNS = {"resource_uid", "resource_name", "resource_type", "resource_platform"}


def migrate_schema(engine: Engine) -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        table_names = set(inspector.get_table_names())

        if "security_findings" not in table_names:
            Base.metadata.create_all(connection)
            return

        security_findings_columns = {
            column_info["name"] for column_info in inspector.get_columns("security_findings")
        }
        if "resource_id" in security_findings_columns:
            Base.metadata.create_all(connection)
            return

        if not _is_legacy_findings_table(security_findings_columns):
            raise RuntimeError(
                "Unsupported schema detected for security_findings; cannot migrate automatically."
            )

        _migrate_legacy_security_findings(connection)
        _sync_identity_sequences(connection, engine.dialect.name)


def _is_legacy_findings_table(column_names: set[str]) -> bool:
    return _LEGACY_REFERENCE_COLUMN in column_names and _LEGACY_RESOURCE_COLUMNS.issubset(column_names)


def _migrate_legacy_security_findings(connection: Any) -> None:
    connection.execute(text("ALTER TABLE security_findings RENAME TO security_findings_legacy"))
    _drop_legacy_indexes(connection)
    Base.metadata.create_all(connection)

    legacy_rows = connection.execute(text("SELECT * FROM security_findings_legacy")).mappings().all()
    if not legacy_rows:
        connection.execute(text("DROP TABLE security_findings_legacy"))
        return

    resource_id_cache: dict[tuple[str, str, str, str], int] = {}

    for row in legacy_rows:
        resource_key = (
            str(row["resource_uid"]),
            str(row["resource_name"]),
            str(row["resource_type"]),
            str(row["resource_platform"]),
        )
        resource_id = resource_id_cache.get(resource_key)
        if resource_id is None:
            resource_insert = connection.execute(
                cast(Any, FindingResourceRecord.__table__).insert().values(
                    uid=resource_key[0],
                    name=resource_key[1],
                    type=resource_key[2],
                    platform=resource_key[3],
                )
            )
            resource_id = int(resource_insert.inserted_primary_key[0])
            resource_id_cache[resource_key] = resource_id

        connection.execute(
            cast(Any, SecurityFindingRecord.__table__).insert().values(
                id=row["id"],
                finding_uid=row["finding_uid"],
                standard=row["standard"],
                schema_version=row["schema_version"],
                status=row["status"],
                severity_id=row["severity_id"],
                severity=row["severity"],
                risk_score=row["risk_score"],
                title=row["title"],
                description=row["description"],
                category_name=row["category_name"],
                class_name=row["class_name"],
                type_name=row["type_name"],
                domain=row["domain"],
                activity_name=row["activity_name"],
                time=_coerce_datetime(row["time"]),
                source=row["source"],
                resource_id=resource_id,
                raw_data=_coerce_json_object(row["raw_data"]),
            )
        )

        reference_payload = _coerce_json_object(row[_LEGACY_REFERENCE_COLUMN])
        for reference_type, reference_values in _extract_reference_values(reference_payload).items():
            for reference_value in reference_values:
                connection.execute(
                    cast(Any, FindingReferenceItemRecord.__table__).insert().values(
                        finding_id=row["id"],
                        reference_type=reference_type,
                        reference_value=reference_value,
                    )
                )

    connection.execute(text("DROP TABLE security_findings_legacy"))


def _extract_reference_values(payload: dict[str, Any]) -> dict[FindingReferenceType, list[str]]:
    reference_map = {
        FindingReferenceType.CVE: payload.get(FindingReferenceType.CVE.value, []),
        FindingReferenceType.CWE: payload.get(FindingReferenceType.CWE.value, []),
        FindingReferenceType.OWASP: payload.get(FindingReferenceType.OWASP.value, []),
        FindingReferenceType.MITRE_ATTACK: payload.get(FindingReferenceType.MITRE_ATTACK.value, []),
    }

    normalized: dict[FindingReferenceType, list[str]] = {}
    for reference_type, values in reference_map.items():
        if isinstance(values, str):
            normalized_values = [values]
        elif isinstance(values, list):
            normalized_values = [str(value) for value in values if str(value).strip()]
        else:
            normalized_values = []
        normalized[reference_type] = sorted(set(normalized_values))

    return normalized


def _drop_legacy_indexes(connection: Any) -> None:
    inspector = inspect(connection)
    for index in inspector.get_indexes("security_findings_legacy"):
        index_name = index.get("name")
        if index_name:
            connection.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    raise RuntimeError(f"Unsupported datetime value during migration: {value!r}")


def _coerce_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    return {}


def _sync_identity_sequences(connection: Any, dialect_name: str) -> None:
    if dialect_name != "postgresql":
        return

    sequence_sync_sql = [
        "SELECT setval(pg_get_serial_sequence('finding_resources','id'), COALESCE((SELECT MAX(id) FROM finding_resources), 1), true)",
        "SELECT setval(pg_get_serial_sequence('security_findings','id'), COALESCE((SELECT MAX(id) FROM security_findings), 1), true)",
        "SELECT setval(pg_get_serial_sequence('finding_reference_items','id'), COALESCE((SELECT MAX(id) FROM finding_reference_items), 1), true)",
    ]
    for sql in sequence_sync_sql:
        connection.execute(text(sql))