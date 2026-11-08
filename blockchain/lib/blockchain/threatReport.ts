/**
 * CyberShield AI — Threat Report Blockchain Types & Normalization
 * ===============================================================
 * Deterministic canonical serialization and Keccak-256 hashing for
 * CyberShield AI UnifiedThreatReport records in TypeScript.
 *
 * Schema version: 1.0
 * Namespace:      CYBERSHIELD_REPORT_V1
 */

import { ethers } from "ethers";

export const NAMESPACE = "CYBERSHIELD_REPORT_V1";

export interface Indicator {
  ioc_type: string;
  value: string;
}

export interface AffectedAsset {
  asset_type: string;
  identifier: string;
}

export interface RemediationStep {
  action: string;
  priority: number;
}

export interface UnifiedThreatReport {
  report_id: string;
  schema_version: string;
  detected_at: string;
  generated_at: string;
  severity: "critical" | "high" | "medium" | "low" | "informational" | "unknown" | string;
  category: string;
  status: string;
  confidence_score: number;
  summary: string;
  description: string;
  indicators: Indicator[];
  affected_assets: AffectedAsset[];
  remediation_steps: RemediationStep[];
  mitre_techniques: string[];
  threat_actor: string;
}

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "informational", "unknown"]);
const VALID_CATEGORIES = new Set([
  "phishing", "malware", "scam", "ddos", "intrusion",
  "ransomware", "data_leak", "vulnerability", "social_engineering",
  "defacement", "other", "unknown"
]);
const VALID_STATUSES = new Set([
  "detected", "investigating", "confirmed", "mitigated",
  "resolved", "false_positive", "completed", "unknown"
]);
const VALID_SCHEMA_VERSIONS = new Set(["1.0", "1.0.0"]);
const ISO_8601_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * Validates and normalizes numeric values for cross-language compatibility.
 * Normalizes whole floats (e.g. 87.0) to integer (87) matching Python int normalization.
 * Preserves decimal fractions (e.g. 87.5).
 */
export function normalizeNumber(
  value: unknown,
  fieldName = "number",
  min = 0,
  max = 100
): number {
  if (typeof value === "boolean") {
    throw new Error(`Field '${fieldName}' must be a number, not boolean.`);
  }

  const num = Number(value);
  if (Number.isNaN(num) || !Number.isFinite(num)) {
    throw new Error(`Field '${fieldName}' must be a valid finite number: ${value}`);
  }

  if (num < min || num > max) {
    throw new Error(`Field '${fieldName}' value ${num} is out of permitted range [${min}, ${max}].`);
  }

  return num;
}

/**
 * Validates all 10 documented required fields of UnifiedThreatReport.
 */
export function validateThreatReport(raw: any): UnifiedThreatReport {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError("Report must be a non-null object.");
  }

  const requiredFields = [
    "report_id", "schema_version", "detected_at", "generated_at",
    "severity", "category", "status", "confidence_score",
    "summary", "description"
  ];

  for (const field of requiredFields) {
    if (raw[field] === undefined || raw[field] === null) {
      throw new Error(`Missing required report field: '${field}'`);
    }
  }

  const report_id = String(raw.report_id).trim();
  if (!report_id) throw new Error("Field 'report_id' cannot be empty.");

  const schema_version = String(raw.schema_version).trim();
  if (!VALID_SCHEMA_VERSIONS.has(schema_version)) {
    throw new Error(`Invalid schema_version '${schema_version}'. Supported: 1.0, 1.0.0`);
  }

  const detected_at = String(raw.detected_at).trim();
  if (!ISO_8601_REGEX.test(detected_at)) {
    throw new Error(`Field 'detected_at' is not a valid ISO-8601 timestamp: '${detected_at}'`);
  }

  const generated_at = String(raw.generated_at).trim();
  if (!ISO_8601_REGEX.test(generated_at)) {
    throw new Error(`Field 'generated_at' is not a valid ISO-8601 timestamp: '${generated_at}'`);
  }

  const severity = String(raw.severity).trim().toLowerCase();
  if (!VALID_SEVERITIES.has(severity)) {
    throw new Error(`Invalid severity '${raw.severity}'.`);
  }

  const category = String(raw.category).trim().toLowerCase();
  if (!VALID_CATEGORIES.has(category)) {
    throw new Error(`Invalid category '${raw.category}'.`);
  }

  const status = String(raw.status).trim().toLowerCase();
  if (!VALID_STATUSES.has(status)) {
    throw new Error(`Invalid status '${raw.status}'.`);
  }

  const confidence_score = normalizeNumber(raw.confidence_score, "confidence_score", 0, 100);

  const summary = String(raw.summary).trim();
  if (!summary) throw new Error("Field 'summary' cannot be empty.");

  const description = String(raw.description).trim();
  if (!description) throw new Error("Field 'description' cannot be empty.");

  return {
    ...raw,
    report_id,
    schema_version: "1.0",
    detected_at,
    generated_at,
    severity,
    category,
    status,
    confidence_score,
    summary,
    description,
  };
}

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 * Produces deterministic, sorted-key JSON matching Python json.dumps(sort_keys=True, separators=(',', ':')).
 */
export function canonicalize(value: any): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return String(value);
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
    return "{" + pairs.join(",") + "}";
  }
  return JSON.stringify(value);
}

/**
 * Normalizes a raw UnifiedThreatReport object for canonical hashing.
 */
export function normalizeThreatReport(raw: any): UnifiedThreatReport {
  const validated = validateThreatReport(raw);

  const indicators = (validated.indicators ?? [])
    .map((ioc: any) => ({
      ioc_type: String(ioc.ioc_type ?? "").trim(),
      value: String(ioc.value ?? "").trim(),
    }))
    .sort((a: Indicator, b: Indicator) => a.ioc_type.localeCompare(b.ioc_type) || a.value.localeCompare(b.value));

  const affected_assets = (validated.affected_assets ?? [])
    .map((a: any) => ({
      asset_type: String(a.asset_type ?? "").trim(),
      identifier: String(a.identifier ?? "").trim(),
    }))
    .sort((a: AffectedAsset, b: AffectedAsset) => a.asset_type.localeCompare(b.asset_type) || a.identifier.localeCompare(b.identifier));

  const remediation_steps = (validated.remediation_steps ?? [])
    .map((s: any) => ({
      action: String(s.action ?? "").trim(),
      priority: Math.floor(Number(s.priority ?? 0)),
    }))
    .sort((a: RemediationStep, b: RemediationStep) => a.priority - b.priority);

  const mitre_techniques = [...(validated.mitre_techniques ?? [])]
    .map(t => String(t).trim())
    .sort();

  return {
    report_id: validated.report_id,
    schema_version: "1.0",
    detected_at: validated.detected_at,
    generated_at: validated.generated_at,
    severity: validated.severity,
    category: validated.category,
    status: validated.status,
    confidence_score: validated.confidence_score,
    summary: validated.summary,
    description: validated.description,
    indicators,
    affected_assets,
    remediation_steps,
    mitre_techniques,
    threat_actor: String(validated.threat_actor ?? "unknown").trim(),
  };
}

/**
 * Computes Keccak-256 hash of canonicalized report.
 */
export function computeReportHash(raw: any): string {
  const normalized = normalizeThreatReport(raw);
  const canonical = canonicalize(normalized);
  return ethers.keccak256(ethers.toUtf8Bytes(canonical));
}

/**
 * Computes deterministic Keccak-256 report ID from report hash and namespace.
 */
export function computeReportId(reportHash: string): string {
  return ethers.keccak256(
    ethers.concat([ethers.toUtf8Bytes(NAMESPACE), ethers.getBytes(reportHash)])
  );
}
