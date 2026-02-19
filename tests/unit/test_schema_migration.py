import json
from datetime import UTC, datetime

from sqlalchemy import inspect, text

from saastesa.api.db import create_db_engine
from saastesa.api.repository import SQLAlchemyFindingStore


def test_migrates_legacy_security_findings_schema(tmp_path) -> None:
    db_path = tmp_path / "legacy.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_path}")
    now = datetime.now(tz=UTC)

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_uid VARCHAR(128) UNIQUE,
                    standard VARCHAR(32),
                    schema_version VARCHAR(32),
                    status VARCHAR(32),
                    severity_id INTEGER,
                    severity VARCHAR(32),
                    risk_score INTEGER,
                    title VARCHAR(256),
                    description VARCHAR(1024),
                    category_name VARCHAR(128),
                    class_name VARCHAR(128),
                    type_name VARCHAR(128),
                    domain VARCHAR(64),
                    activity_name VARCHAR(64),
                    time DATETIME,
                    source VARCHAR(128),
                    resource_uid VARCHAR(256),
                    resource_name VARCHAR(256),
                    resource_type VARCHAR(128),
                    resource_platform VARCHAR(128),
                    references_json JSON,
                    raw_data JSON
                )
                """
            )
        )

        payload = {
            "id": 1,
            "finding_uid": "legacy-1",
            "standard": "OCSF",
            "schema_version": "1.1.0",
            "status": "open",
            "severity_id": 5,
            "severity": "critical",
            "risk_score": 90,
            "title": "Legacy finding",
            "description": "from old schema",
            "category_name": "Infrastructure Security",
            "class_name": "Security Finding",
            "type_name": "Privilege Escalation",
            "domain": "infrastructure",
            "activity_name": "Create",
            "time": now,
            "source": "legacy",
            "resource_uid": "res-1",
            "resource_name": "prod-api",
            "resource_type": "service",
            "resource_platform": "aws",
            "references_json": json.dumps({"cve": ["CVE-2026-0001"], "cwe": ["CWE-269"]}),
            "raw_data": json.dumps({"legacy": True}),
        }
        connection.execute(
            text(
                """
                INSERT INTO security_findings (
                    id, finding_uid, standard, schema_version, status, severity_id, severity,
                    risk_score, title, description, category_name, class_name, type_name,
                    domain, activity_name, time, source, resource_uid, resource_name,
                    resource_type, resource_platform, references_json, raw_data
                ) VALUES (
                    :id, :finding_uid, :standard, :schema_version, :status, :severity_id, :severity,
                    :risk_score, :title, :description, :category_name, :class_name, :type_name,
                    :domain, :activity_name, :time, :source, :resource_uid, :resource_name,
                    :resource_type, :resource_platform, :references_json, :raw_data
                )
                """
            ),
            payload,
        )

    store = SQLAlchemyFindingStore(engine)
    store.init()

    inspector = inspect(engine)
    assert "security_findings_legacy" not in inspector.get_table_names()
    assert "finding_resources" in inspector.get_table_names()
    assert "finding_reference_items" in inspector.get_table_names()
    assert "resource_id" in {column["name"] for column in inspector.get_columns("security_findings")}

    findings = store.list(limit=10)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.finding_uid == "legacy-1"
    assert finding.resource.uid == "res-1"
    assert finding.references.cve == ("CVE-2026-0001",)
    assert finding.references.cwe == ("CWE-269",)
