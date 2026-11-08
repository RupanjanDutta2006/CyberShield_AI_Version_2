// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ThreatReportRegistry
 * @author CyberShield AI — Member 3 (Blockchain & Web3)
 * @notice Immutable on-chain registry for CyberShield AI threat reports.
 *         Stores ONLY cryptographic fingerprints — never sensitive data.
 *
 * Security principles:
 *   - No report contents, user data, API keys, or IP addresses on-chain.
 *   - Only report ID, Keccak-256 hash, timestamp, and registrant address.
 *   - Role-governed registration: only authorized backend registrars can write.
 *   - Public read verification: anyone can verify report authenticity.
 */
contract ThreatReportRegistry {

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    /// @dev Fixed namespace prevents cross-application hash collisions.
    string private constant NAMESPACE = "CYBERSHIELD_REPORT_V1";

    // ──────────────────────────────────────────────
    //  Access Control & Governance
    // ──────────────────────────────────────────────

    address public owner;
    mapping(address => bool) public isAuthorizedRegistrar;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RegistrarAuthorized(address indexed registrar);
    event RegistrarRevoked(address indexed registrar);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    // ──────────────────────────────────────────────
    //  Data structures
    // ──────────────────────────────────────────────

    struct Report {
        bytes32 reportId;
        bytes32 reportHash;
        address registeredBy;
        uint256 registeredAt;
    }

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @dev Report ID  →  full Report record
    mapping(bytes32 => Report) private reports;

    /// @dev Report hash  →  already registered?
    mapping(bytes32 => bool) public hashExists;

    /// @dev Running count of registered reports
    uint256 public reportCount;

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event ReportRegistered(
        bytes32 indexed reportId,
        bytes32 indexed reportHash,
        address indexed registeredBy,
        uint256 registeredAt
    );

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        isAuthorizedRegistrar[msg.sender] = true;
        emit RegistrarAuthorized(msg.sender);
    }

    // ──────────────────────────────────────────────
    //  Governance functions
    // ──────────────────────────────────────────────

    /**
     * @notice Authorize an address (e.g. backend service wallet) to register reports.
     */
    function authorizeRegistrar(address registrar) external onlyOwner {
        require(registrar != address(0), "Invalid registrar address");
        require(!isAuthorizedRegistrar[registrar], "Registrar already authorized");
        isAuthorizedRegistrar[registrar] = true;
        emit RegistrarAuthorized(registrar);
    }

    /**
     * @notice Revoke registration authority from an address.
     */
    function revokeRegistrar(address registrar) external onlyOwner {
        require(registrar != address(0), "Invalid registrar address");
        require(registrar != owner, "Cannot revoke contract owner");
        require(isAuthorizedRegistrar[registrar], "Registrar not authorized");
        isAuthorizedRegistrar[registrar] = false;
        emit RegistrarRevoked(registrar);
    }

    /**
     * @notice Transfer contract ownership to a new administrator address.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        address previousOwner = owner;
        owner = newOwner;
        isAuthorizedRegistrar[newOwner] = true;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    // ──────────────────────────────────────────────
    //  Pure helpers
    // ──────────────────────────────────────────────

    /**
     * @notice Derive a deterministic report ID from a report hash.
     * @dev    ID = keccak256(NAMESPACE ‖ reportHash)
     *         Identical hashes always produce the same ID.
     */
    function generateReportId(
        bytes32 reportHash
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(NAMESPACE, reportHash)
        );
    }

    // ──────────────────────────────────────────────
    //  Write: register
    // ──────────────────────────────────────────────

    /**
     * @notice Register a new threat report on-chain.
     * @param  reportHash  Keccak-256 fingerprint of the canonical report.
     * @return reportId    Deterministic identifier derived from the hash.
     *
     * Requirements:
     *   - Caller must be the contract owner or an authorized registrar.
     *   - reportHash must not be zero.
     *   - The same hash cannot be registered twice (duplicate protection).
     */
    function registerReport(
        bytes32 reportHash
    ) external returns (bytes32) {
        // ── Authorization guard ───────────────────
        require(
            msg.sender == owner || isAuthorizedRegistrar[msg.sender],
            "Unauthorized registrar"
        );

        require(
            reportHash != bytes32(0),
            "Invalid report hash"
        );

        // Derive deterministic ID
        bytes32 reportId = generateReportId(reportHash);

        // ── Duplicate guards ──────────────────────
        require(
            !hashExists[reportHash],
            "Report already registered"
        );
        require(
            reports[reportId].registeredAt == 0,
            "Report ID already exists"
        );

        // ── Persist ───────────────────────────────
        reports[reportId] = Report({
            reportId:     reportId,
            reportHash:   reportHash,
            registeredBy: msg.sender,
            registeredAt: block.timestamp
        });

        hashExists[reportHash] = true;
        reportCount += 1;

        emit ReportRegistered(
            reportId,
            reportHash,
            msg.sender,
            block.timestamp
        );

        return reportId;
    }

    // ──────────────────────────────────────────────
    //  Read: verify (Public)
    // ──────────────────────────────────────────────

    /**
     * @notice Verify that a report ID + hash pair is registered and consistent.
     * @return True only when:
     *         1. A record exists for `reportId`.
     *         2. Its stored hash equals `reportHash`.
     *         3. `generateReportId(reportHash)` reproduces `reportId`.
     */
    function verifyReport(
        bytes32 reportId,
        bytes32 reportHash
    ) external view returns (bool) {

        Report memory r = reports[reportId];

        if (r.registeredAt == 0)               return false; // not found
        if (r.reportHash  != reportHash)       return false; // hash mismatch
        if (generateReportId(reportHash) != reportId)
                                                return false; // ID mismatch
        return true;
    }

    // ──────────────────────────────────────────────
    //  Read: metadata (Public)
    // ──────────────────────────────────────────────

    /**
     * @notice Retrieve the public metadata of a registered report.
     * @return reportId, reportHash, registeredBy, registeredAt
     */
    function getReport(
        bytes32 reportId
    ) external view returns (
        bytes32,
        bytes32,
        address,
        uint256
    ) {
        Report memory r = reports[reportId];

        require(
            r.registeredAt != 0,
            "Report not found"
        );

        return (
            r.reportId,
            r.reportHash,
            r.registeredBy,
            r.registeredAt
        );
    }
}
