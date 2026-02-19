from datetime import datetime
from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from saastesa.core.contracts import (
    FindingActivity,
    FindingClass,
    FindingDomain,
    FindingReferenceType,
    FindingSeverity,
    FindingStandard,
    FindingStatus,
    JSONValue,
)


class Base(DeclarativeBase):
    pass


class FindingResourceRecord(Base):
    __tablename__ = "finding_resources"
    __table_args__ = (
        UniqueConstraint(
            "uid",
            "name",
            "type",
            "platform",
            name="uq_finding_resources_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uid: Mapped[str] = mapped_column(String(256), index=True)
    name: Mapped[str] = mapped_column(String(256))
    type: Mapped[str] = mapped_column(String(128))
    platform: Mapped[str] = mapped_column(String(128))


class SecurityFindingRecord(Base):
    __tablename__ = "security_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_uid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    standard: Mapped[FindingStandard] = mapped_column(
        SAEnum(FindingStandard, name="finding_standard", native_enum=False)
    )
    schema_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, name="finding_status", native_enum=False)
    )
    severity_id: Mapped[int] = mapped_column(Integer)
    severity: Mapped[FindingSeverity] = mapped_column(
        SAEnum(FindingSeverity, name="finding_severity", native_enum=False)
    )
    risk_score: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(String(1024))
    category_name: Mapped[str] = mapped_column(String(128))
    class_name: Mapped[FindingClass] = mapped_column(
        SAEnum(FindingClass, name="finding_class", native_enum=False)
    )
    type_name: Mapped[str] = mapped_column(String(128))
    domain: Mapped[FindingDomain] = mapped_column(
        SAEnum(FindingDomain, name="finding_domain", native_enum=False), index=True
    )
    activity_name: Mapped[FindingActivity] = mapped_column(
        SAEnum(FindingActivity, name="finding_activity", native_enum=False)
    )
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(128), index=True)

    resource_id: Mapped[int] = mapped_column(ForeignKey("finding_resources.id"), index=True)
    raw_data: Mapped[dict[str, JSONValue]] = mapped_column(JSON)
    resource: Mapped[FindingResourceRecord] = relationship()
    reference_items: Mapped[list["FindingReferenceItemRecord"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingReferenceItemRecord(Base):
    __tablename__ = "finding_reference_items"
    __table_args__ = (
        UniqueConstraint("finding_id", "reference_type", "reference_value", name="uq_finding_reference_item"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("security_findings.id"), index=True)
    reference_type: Mapped[FindingReferenceType] = mapped_column(
        SAEnum(FindingReferenceType, name="finding_reference_type", native_enum=False),
        index=True,
    )
    reference_value: Mapped[str] = mapped_column(String(256), index=True)

    finding: Mapped[SecurityFindingRecord] = relationship(back_populates="reference_items")
