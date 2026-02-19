export type FindingStandard = "OCSF";
export type FindingSchemaVersion = "1.1.0";
export type FindingStatus = "open" | "in_progress" | "resolved" | "closed" | "suppressed";
export type FindingSeverity = "informational" | "low" | "medium" | "high" | "critical";
export type FindingDomain =
  | "application"
  | "infrastructure"
  | "identity"
  | "cloud"
  | "container"
  | "other";
export type FindingClass = "Security Finding";
export type FindingActivity = "Create";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | { [key: string]: JsonValue } | JsonValue[];

export type FindingsSummary = {
  low: number;
  medium: number;
  high: number;
  critical: number;
};

export type SecurityFinding = {
  finding_uid: string;
  standard: FindingStandard;
  schema_version: FindingSchemaVersion;
  status: FindingStatus;
  severity_id: number;
  severity: FindingSeverity;
  risk_score: number;
  title: string;
  description: string;
  category_name: string;
  class_name: FindingClass;
  type_name: string;
  domain: FindingDomain;
  activity_name: FindingActivity;
  time: string;
  source: string;
  resource: {
    uid: string;
    name: string;
    type: string;
    platform: string;
  };
  references: {
    cve: string[];
    cwe: string[];
    owasp: string[];
    mitre_attack: string[];
  };
  raw_data: Record<string, JsonValue>;
};
