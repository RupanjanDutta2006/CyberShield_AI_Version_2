/**
 * Cross-Language Hash Consistency & Schema Validation Tests
 * =========================================================
 * Verifies that TypeScript and Python produce identical canonical JSON,
 * report hashes, and report IDs across multiple realistic reports,
 * integer/decimal confidence scores, and boundary values.
 *
 * Can be run standalone:
 *   node test/hash_consistency.mjs
 * Or via Hardhat/Mocha:
 *   npx hardhat test
 */

import { ethers } from "ethers";
import assert from "assert";

const NAMESPACE = "CYBERSHIELD_REPORT_V1";

// ── canonicalize ──────────────────────────────────────────────────
export function canonicalize(value) {
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

// ── normalizeNumber ───────────────────────────────────────────────
export function normalizeNumber(value, fieldName = "number", min = 0, max = 100) {
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

// ── normalizeThreatReport ─────────────────────────────────────────
export function normalizeThreatReport(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError("Report must be an object.");
  }

  const requiredFields = [
    "report_id", "schema_version", "detected_at", "generated_at",
    "severity", "category", "status", "confidence_score",
    "summary", "description"
  ];

  for (const f of requiredFields) {
    if (raw[f] === undefined || raw[f] === null) {
      throw new Error(`Missing required field: '${f}'`);
    }
  }

  const confidence_score = normalizeNumber(raw.confidence_score, "confidence_score", 0, 100);

  const indicators = (raw.indicators ?? [])
    .map(ioc => ({
      ioc_type: String(ioc.ioc_type ?? "").trim(),
      value: String(ioc.value ?? "").trim(),
    }))
    .sort((a, b) => a.ioc_type.localeCompare(b.ioc_type) || a.value.localeCompare(b.value));

  const affected_assets = (raw.affected_assets ?? [])
    .map(a => ({
      asset_type: String(a.asset_type ?? "").trim(),
      identifier: String(a.identifier ?? "").trim(),
    }))
    .sort((a, b) => a.asset_type.localeCompare(b.asset_type) || a.identifier.localeCompare(b.identifier));

  const remediation_steps = (raw.remediation_steps ?? [])
    .map(s => ({
      action: String(s.action ?? "").trim(),
      priority: Math.floor(Number(s.priority ?? 0)),
    }))
    .sort((a, b) => a.priority - b.priority);

  const mitre_techniques = [...(raw.mitre_techniques ?? [])]
    .map(t => String(t).trim())
    .sort();

  return {
    report_id: String(raw.report_id).trim(),
    schema_version: "1.0",
    detected_at: String(raw.detected_at).trim(),
    generated_at: String(raw.generated_at).trim(),
    severity: String(raw.severity).trim().toLowerCase(),
    category: String(raw.category).trim().toLowerCase(),
    status: String(raw.status).trim().toLowerCase(),
    confidence_score,
    summary: String(raw.summary).trim(),
    description: String(raw.description).trim(),
    indicators,
    affected_assets,
    remediation_steps,
    mitre_techniques,
    threat_actor: String(raw.threat_actor ?? "unknown").trim(),
  };
}

export function computeReportHash(raw) {
  const normalized = normalizeThreatReport(raw);
  const canonical = canonicalize(normalized);
  return ethers.keccak256(ethers.toUtf8Bytes(canonical));
}

export function computeReportId(reportHash) {
  return ethers.keccak256(
    ethers.concat([ethers.toUtf8Bytes(NAMESPACE), ethers.getBytes(reportHash)])
  );
}

// ── Test Vectors matching Python test outputs ────────────────────
export const SAMPLE_REPORT = {
  report_id: "CSR-20261107-00001",
  schema_version: "1.0",
  detected_at: "2026-11-07T10:00:00.000Z",
  generated_at: "2026-11-07T10:05:00.000Z",
  severity: "high",
  category: "phishing",
  status: "detected",
  confidence_score: 87,
  summary: "Credential harvesting phishing campaign targeting corporate email.",
  description: "AI detected a phishing campaign using spoofed login pages to harvest credentials. Multiple users received emails with malicious links.",
  indicators: [
    { ioc_type: "domain", value: "secure-login-verify.example.com" },
    { ioc_type: "hash", value: "d41d8cd98f00b204e9800998ecf8427e" },
  ],
  affected_assets: [
    { asset_type: "service", identifier: "corporate-email" },
    { asset_type: "user", identifier: "user-group-finance" },
  ],
  remediation_steps: [
    { priority: 1, action: "Block domain secure-login-verify.example.com at DNS level" },
    { priority: 2, action: "Force password reset for all users who clicked the link" },
    { priority: 3, action: "Enable MFA for all corporate email accounts" },
  ],
  mitre_techniques: ["T1566", "T1078"],
  threat_actor: "unknown",
};

// Known Python outputs
const VECTORS = [
  {
    name: "Integer confidence score (87)",
    report: { ...SAMPLE_REPORT, confidence_score: 87 },
    expectedHash: "0xd5469a33795e145ad89bc2e577d20545f0e5b6e72b49b7419c78ef4f630970f7",
    expectedId: "0x56ab21e4ee1c49b609e04024f8c9062afb6e1fb126101bac1a64858ade9c6ca9",
  },
  {
    name: "Float whole confidence score (87.0 -> 87)",
    report: { ...SAMPLE_REPORT, confidence_score: 87.0 },
    expectedHash: "0xd5469a33795e145ad89bc2e577d20545f0e5b6e72b49b7419c78ef4f630970f7",
    expectedId: "0x56ab21e4ee1c49b609e04024f8c9062afb6e1fb126101bac1a64858ade9c6ca9",
  },
  {
    name: "Decimal confidence score (87.5)",
    report: { ...SAMPLE_REPORT, confidence_score: 87.5 },
    expectedHash: "0xbcfba7ec224c8394ca2310409789afde314da308e3c691bc4d2d0414c811e857",
    expectedId: "0x41d8c123e6274a105b39db15e23918d14e39c4c43a64f28b6730565d6c27dbde",
  },
  {
    name: "Lower boundary confidence score (0)",
    report: { ...SAMPLE_REPORT, confidence_score: 0 },
    expectedHash: "0x07af08bec2e715bb36840f765339a6b5ab9080104d345be999ccd8db53aa6e25",
    expectedId: "0xbd9d8f894035140a692e48758bf84d762e4c0d16cb47acdc78b659dd4f420dbb",
  },
  {
    name: "Upper boundary confidence score (100)",
    report: { ...SAMPLE_REPORT, confidence_score: 100 },
    expectedHash: "0xbdcb1ad3788572723f7242d9e93c797adc5c3a13afcc5b7af19e770ffd1f2bdd",
    expectedId: "0x4e7cfe2f6529a1ee854c9515944c8460f2d9a1a4a4da0c4d6dbf6077f4baad92",
  },
];

export function runTests() {
  console.log("=".repeat(70));
  console.log("  CyberShield AI — Cross-Language Hash Consistency Suite");
  console.log("=".repeat(70));

  for (const v of VECTORS) {
    const hash = computeReportHash(v.report);
    const id = computeReportId(hash);
    assert.strictEqual(hash, v.expectedHash, `Hash mismatch for ${v.name}`);
    assert.strictEqual(id, v.expectedId, `ID mismatch for ${v.name}`);
    console.log(`  ✅ [PASS] ${v.name}`);
  }

  // Tamper detection test
  const tampered = { ...SAMPLE_REPORT, summary: "Tampered content" };
  const tamperedHash = computeReportHash(tampered);
  assert.notStrictEqual(tamperedHash, VECTORS[0].expectedHash, "Tampered report should produce different hash");
  console.log("  ✅ [PASS] Tamper detection test");

  // Invalid report rejection test
  assert.throws(() => {
    normalizeThreatReport({ ...SAMPLE_REPORT, confidence_score: 150 });
  }, "Out-of-range confidence score should throw");
  console.log("  ✅ [PASS] Out-of-range confidence score rejected");

  assert.throws(() => {
    normalizeThreatReport({ ...SAMPLE_REPORT, confidence_score: NaN });
  }, "NaN confidence score should throw");
  console.log("  ✅ [PASS] NaN confidence score rejected");

  console.log("=".repeat(70));
  console.log("  ✅ All cross-language consistency checks PASSED.");
  console.log("=".repeat(70));
}

// If running in Mocha
if (typeof describe === "function") {
  describe("Cross-Language Hash Consistency", function () {
    for (const v of VECTORS) {
      it(`Should match Python hash and ID for: ${v.name}`, function () {
        const hash = computeReportHash(v.report);
        const id = computeReportId(hash);
        assert.strictEqual(hash, v.expectedHash);
        assert.strictEqual(id, v.expectedId);
      });
    }

    it("Should detect tampering with different hash", function () {
      const tampered = { ...SAMPLE_REPORT, summary: "Tampered content" };
      const tamperedHash = computeReportHash(tampered);
      assert.notStrictEqual(tamperedHash, VECTORS[0].expectedHash);
    });

    it("Should reject invalid confidence scores", function () {
      assert.throws(() => normalizeThreatReport({ ...SAMPLE_REPORT, confidence_score: 150 }));
      assert.throws(() => normalizeThreatReport({ ...SAMPLE_REPORT, confidence_score: -5 }));
      assert.throws(() => normalizeThreatReport({ ...SAMPLE_REPORT, confidence_score: NaN }));
      assert.throws(() => normalizeThreatReport({ ...SAMPLE_REPORT, confidence_score: true }));
    });
  });
} else {
  runTests();
}
