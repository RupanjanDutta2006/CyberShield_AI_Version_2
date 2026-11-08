import * as THREE from 'three';

export interface ChapterKeyframe {
  chapterIndex: number;
  chapterNumber: string;
  title: string;
  kicker: string;
  headline: string;
  description: string;
  stats: { label: string; value: string }[];
  ctaLabel: string;
  ctaRoute: string;
  cameraPos: THREE.Vector3;
  cameraLookAt: THREE.Vector3;
  laserColor: THREE.Color;
  laserIntensity: number;
  monolithSpread: number;
  shieldScale: number;
  shieldRotationSpeed: number;
  particleSpeed: number;
}

export const CHAPTERS: ChapterKeyframe[] = [
  {
    chapterIndex: 0,
    chapterNumber: '00',
    title: 'CYBERSHIELD AI',
    kicker: 'AI-Powered Threat Detection & Digital Trust Intelligence',
    headline: 'Intelligence Before Impact.',
    description:
      'Autonomous cyber threat triage across suspicious messages, deceptive domains, phishing networks, and social engineering attacks.',
    stats: [
      { label: 'THREAT ENGINE', value: 'ACTIVE' },
      { label: 'EVIDENCE ACCURACY', value: '99.4%' },
      { label: 'VERIFICATION', value: 'RFC 8785' },
    ],
    ctaLabel: 'Start Exploration',
    ctaRoute: '/dashboard',
    cameraPos: new THREE.Vector3(0, 1.2, 13.5),
    cameraLookAt: new THREE.Vector3(0, 0, 0),
    laserColor: new THREE.Color('#ff1e38'),
    laserIntensity: 1.0,
    monolithSpread: 5.2,
    shieldScale: 1.0,
    shieldRotationSpeed: 0.008,
    particleSpeed: 0.002,
  },
  {
    chapterIndex: 1,
    chapterNumber: '01',
    title: 'THE SIGNAL',
    kicker: 'Communication Analysis',
    headline: 'Every signal has a story.',
    description:
      'Malicious communication disguises itself inside everyday emails, SMS alerts, and urgent Telegram messages. CyberShield isolates syntactic anomalies, psychological urgency hooks, and credential-harvesting patterns in real time.',
    stats: [
      { label: 'INGESTION', value: 'MULTI-MODAL' },
      { label: 'URGENCY METRIC', value: 'CALIBRATED' },
      { label: 'DEFENSE LEVEL', value: 'TIER-1' },
    ],
    ctaLabel: 'Analyse a Message',
    ctaRoute: '/message-analyzer',
    cameraPos: new THREE.Vector3(-2.8, 1.6, 8.8),
    cameraLookAt: new THREE.Vector3(-0.6, 0.4, 0),
    laserColor: new THREE.Color('#ff2a3a'),
    laserIntensity: 1.4,
    monolithSpread: 4.6,
    shieldScale: 1.05,
    shieldRotationSpeed: 0.012,
    particleSpeed: 0.0035,
  },
  {
    chapterIndex: 2,
    chapterNumber: '02',
    title: 'THE ATTACK SURFACE',
    kicker: 'Domain & Infrastructure Intelligence',
    headline: 'Every link leads somewhere.',
    description:
      'A single click opens into an elaborate adversary infrastructure. We safe-defang hostile URLs, interrogate live global threat feeds (URLhaus, PhishTank), and inspect IP-literal hosts and deceptive top-level domains without payload execution.',
    stats: [
      { label: 'SAFE DEFANGING', value: 'ENABLED' },
      { label: 'HOST CORRELATION', value: 'URLHAUS + PHISHTANK' },
      { label: 'PAYLOAD EXECUTION', value: 'ZERO-FETCH' },
    ],
    ctaLabel: 'Investigate a URL',
    ctaRoute: '/scanner',
    cameraPos: new THREE.Vector3(3.4, 3.2, 10.2),
    cameraLookAt: new THREE.Vector3(0.5, 0.2, 0),
    laserColor: new THREE.Color('#ff3b20'),
    laserIntensity: 1.25,
    monolithSpread: 6.2,
    shieldScale: 0.95,
    shieldRotationSpeed: 0.01,
    particleSpeed: 0.003,
  },
  {
    chapterIndex: 3,
    chapterNumber: '03',
    title: 'INTELLIGENCE IN MOTION',
    kicker: 'Resilient Multi-Provider AI Engine',
    headline: 'Understand what hides in the message.',
    description:
      'Resilient zero-crash AI orchestration. High-throughput Groq Cloud primary fails over smoothly to Google Gemini, then OpenAI, and finally our deterministic offline heuristic engine. Hardened with strict prompt-injection sandboxing.',
    stats: [
      { label: 'FAILOVER HIERARCHY', value: 'GROQ → GEMINI → OPENAI' },
      { label: 'INJECTION DEFENSE', value: 'DATA-ENCAPSULATED' },
      { label: 'HEURISTIC FALLBACK', value: 'OFFLINE-READY' },
    ],
    ctaLabel: 'Explore AI Engine',
    ctaRoute: '/message-analyzer',
    cameraPos: new THREE.Vector3(0, 0.4, 6.2),
    cameraLookAt: new THREE.Vector3(0, 0, 0),
    laserColor: new THREE.Color('#ff1844'),
    laserIntensity: 1.8,
    monolithSpread: 3.8,
    shieldScale: 1.15,
    shieldRotationSpeed: 0.016,
    particleSpeed: 0.005,
  },
  {
    chapterIndex: 4,
    chapterNumber: '04',
    title: 'THE EVIDENCE',
    kicker: 'Forensic Extraction & Grounding',
    headline: 'Suspicion becomes structured intelligence.',
    description:
      'Eliminating hallucinations through verbatim evidence extraction. Our EvidenceValidator audits every flagged quote directly against raw message bytes, extracting active phone numbers (+91 formats), target domains, and threat vectors.',
    stats: [
      { label: 'VERBATIM QUOTES', value: '100% GROUNDED' },
      { label: 'INDICATORS', value: 'TEL / URL / EMAIL' },
      { label: 'SCORING MATRIX', value: 'DETERMINISTIC' },
    ],
    ctaLabel: 'View Threat Reports',
    ctaRoute: '/history',
    cameraPos: new THREE.Vector3(2.2, -1.8, 8.4),
    cameraLookAt: new THREE.Vector3(0.2, -0.2, 0),
    laserColor: new THREE.Color('#ff0055'),
    laserIntensity: 1.3,
    monolithSpread: 4.8,
    shieldScale: 1.0,
    shieldRotationSpeed: 0.009,
    particleSpeed: 0.0025,
  },
  {
    chapterIndex: 5,
    chapterNumber: '05',
    title: 'VERIFIABLE TRUST',
    kicker: 'Cryptographic Integrity & Blockchain Proof',
    headline: 'Evidence should leave a verifiable trace.',
    description:
      'Guaranteed tamper-evident forensic custody. Normalized RFC 8785 canonical JSON formatting generates an immutable SHA-256 fingerprint anchored to on-chain decentralized EVM ledger proofs (Ethereum Sepolia).',
    stats: [
      { label: 'CANONICAL HASH', value: 'RFC 8785 SHA-256' },
      { label: 'TAMPER DETECTION', value: 'MATHEMATICAL' },
      { label: 'LEDGER PROOF', value: 'SEPOLIA / WEB3' },
    ],
    ctaLabel: 'Explore Verification',
    ctaRoute: '/history',
    cameraPos: new THREE.Vector3(-3.0, 0.8, 7.5),
    cameraLookAt: new THREE.Vector3(-0.4, 0.1, 0),
    laserColor: new THREE.Color('#00f5a0'), // Transitions to trust cyan/teal
    laserIntensity: 1.6,
    monolithSpread: 5.5,
    shieldScale: 1.1,
    shieldRotationSpeed: 0.014,
    particleSpeed: 0.003,
  },
  {
    chapterIndex: 6,
    chapterNumber: '06',
    title: "WHAT'S NEXT",
    kicker: 'Unified Autonomous Threat Defense',
    headline: 'Make your next decision with confidence.',
    description:
      'The complete cybersecurity ecosystem united: Real-time message triage, URL intelligence, verifiable forensic reporting, and deterministic risk scoring ready for immediate enterprise deployment.',
    stats: [
      { label: 'STATUS', value: 'OPERATIONAL' },
      { label: 'API ENDPOINTS', value: 'ONLINE' },
      { label: 'INTELLIGENCE', value: 'BEFORE IMPACT' },
    ],
    ctaLabel: 'Launch Full Platform',
    ctaRoute: '/dashboard',
    cameraPos: new THREE.Vector3(0, 2.0, 15.0),
    cameraLookAt: new THREE.Vector3(0, 0, 0),
    laserColor: new THREE.Color('#22d3ee'),
    laserIntensity: 1.5,
    monolithSpread: 6.8,
    shieldScale: 1.25,
    shieldRotationSpeed: 0.008,
    particleSpeed: 0.002,
  },
];

/**
 * Interpolate camera and scene parameters based on continuous scroll progress (0.0 to 6.0)
 */
export function interpolateKeyframe(progress: number) {
  const clamped = Math.max(0, Math.min(6, progress));
  const floorIdx = Math.floor(clamped);
  const ceilIdx = Math.min(6, floorIdx + 1);
  const alpha = clamped - floorIdx;

  const k1 = CHAPTERS[floorIdx];
  const k2 = CHAPTERS[ceilIdx] || k1;

  const currentPos = new THREE.Vector3().lerpVectors(k1.cameraPos, k2.cameraPos, alpha);
  const currentLookAt = new THREE.Vector3().lerpVectors(k1.cameraLookAt, k2.cameraLookAt, alpha);
  const currentColor = new THREE.Color().lerpColors(k1.laserColor, k2.laserColor, alpha);
  const currentIntensity = THREE.MathUtils.lerp(k1.laserIntensity, k2.laserIntensity, alpha);
  const currentSpread = THREE.MathUtils.lerp(k1.monolithSpread, k2.monolithSpread, alpha);
  const currentShieldScale = THREE.MathUtils.lerp(k1.shieldScale, k2.shieldScale, alpha);
  const currentRotationSpeed = THREE.MathUtils.lerp(k1.shieldRotationSpeed, k2.shieldRotationSpeed, alpha);

  return {
    chapter: k1,
    nextChapter: k2,
    alpha,
    cameraPos: currentPos,
    cameraLookAt: currentLookAt,
    laserColor: currentColor,
    laserIntensity: currentIntensity,
    monolithSpread: currentSpread,
    shieldScale: currentShieldScale,
    rotationSpeed: currentRotationSpeed,
  };
}
