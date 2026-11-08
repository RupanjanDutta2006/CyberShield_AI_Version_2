const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatReportRegistry", function () {

    let registry;
    let owner;
    let otherAccount;
    let unauthorizedAccount;

    beforeEach(async function () {
        [owner, otherAccount, unauthorizedAccount] = await ethers.getSigners();

        const Registry = await ethers.getContractFactory(
            "ThreatReportRegistry"
        );
        registry = await Registry.deploy();
        await registry.waitForDeployment();
    });

    // ────────────────────────────────────────────────
    //  1. Registration tests
    // ────────────────────────────────────────────────

    describe("registerReport", function () {

        it("Should register a new report and emit event", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );

            await expect(
                registry.registerReport(hash)
            ).to.emit(registry, "ReportRegistered");
        });

        it("Should increment reportCount after registration", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );

            expect(await registry.reportCount()).to.equal(0);
            await registry.registerReport(hash);
            expect(await registry.reportCount()).to.equal(1);
        });

        it("Should reject a zero hash", async function () {
            const zeroHash = ethers.ZeroHash;

            await expect(
                registry.registerReport(zeroHash)
            ).to.be.revertedWith("Invalid report hash");
        });

        it("Should reject duplicate report hashes", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );

            await registry.registerReport(hash);

            await expect(
                registry.registerReport(hash)
            ).to.be.revertedWith("Report already registered");
        });

        it("Should allow different reports from different accounts", async function () {
            const hashA = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const hashB = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report B")
            );

            await registry.connect(owner).registerReport(hashA);
            await registry.connect(owner).authorizeRegistrar(otherAccount.address);
            await registry.connect(otherAccount).registerReport(hashB);

            expect(await registry.reportCount()).to.equal(2);
        });

        it("Should store the correct registrant address", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const reportId = await registry.generateReportId(hash);

            await registry.connect(owner).authorizeRegistrar(otherAccount.address);
            await registry.connect(otherAccount).registerReport(hash);

            const [, , registeredBy,] = await registry.getReport(reportId);
            expect(registeredBy).to.equal(otherAccount.address);
        });
    });

    // ────────────────────────────────────────────────
    //  2. Verification tests
    // ────────────────────────────────────────────────

    describe("verifyReport", function () {

        it("Should verify the original report as true", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const id = await registry.generateReportId(hash);

            await registry.registerReport(hash);

            const result = await registry.verifyReport(id, hash);
            expect(result).to.equal(true);
        });

        it("Should reject a modified report hash", async function () {
            const originalHash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const modifiedHash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report B")
            );
            const id = await registry.generateReportId(originalHash);

            await registry.registerReport(originalHash);

            const result = await registry.verifyReport(id, modifiedHash);
            expect(result).to.equal(false);
        });

        it("Should return false for an unregistered report", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Unknown Report")
            );
            const id = await registry.generateReportId(hash);

            const result = await registry.verifyReport(id, hash);
            expect(result).to.equal(false);
        });

        it("Should return false for mismatched ID and hash", async function () {
            const hashA = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const hashB = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report B")
            );

            // Register report A
            await registry.registerReport(hashA);

            // Try to verify with report A's ID but report B's hash
            const idA = await registry.generateReportId(hashA);
            const result = await registry.verifyReport(idA, hashB);
            expect(result).to.equal(false);
        });
    });

    // ────────────────────────────────────────────────
    //  3. Report ID generation tests
    // ────────────────────────────────────────────────

    describe("generateReportId", function () {

        it("Should produce deterministic IDs", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );

            const id1 = await registry.generateReportId(hash);
            const id2 = await registry.generateReportId(hash);

            expect(id1).to.equal(id2);
        });

        it("Should produce different IDs for different hashes", async function () {
            const hashA = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const hashB = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report B")
            );

            const idA = await registry.generateReportId(hashA);
            const idB = await registry.generateReportId(hashB);

            expect(idA).to.not.equal(idB);
        });
    });

    // ────────────────────────────────────────────────
    //  4. getReport tests
    // ────────────────────────────────────────────────

    describe("getReport", function () {

        it("Should return correct metadata for a registered report", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );
            const expectedId = await registry.generateReportId(hash);

            await registry.registerReport(hash);

            const [reportId, reportHash, registeredBy, registeredAt] =
                await registry.getReport(expectedId);

            expect(reportId).to.equal(expectedId);
            expect(reportHash).to.equal(hash);
            expect(registeredBy).to.equal(owner.address);
            expect(registeredAt).to.be.greaterThan(0);
        });

        it("Should revert for a non-existent report", async function () {
            const fakeId = ethers.keccak256(
                ethers.toUtf8Bytes("nonexistent")
            );

            await expect(
                registry.getReport(fakeId)
            ).to.be.revertedWith("Report not found");
        });
    });

    // ────────────────────────────────────────────────
    //  5. Authorization & Governance tests (Phase 9)
    // ────────────────────────────────────────────────

    describe("Authorization & Governance", function () {

        it("Should reject registration from unauthorized accounts", async function () {
            const hash = ethers.keccak256(ethers.toUtf8Bytes("Threat Report Unauthorized"));

            await expect(
                registry.connect(unauthorizedAccount).registerReport(hash)
            ).to.be.revertedWith("Unauthorized registrar");
        });

        it("Should allow owner to authorize a new registrar", async function () {
            await expect(
                registry.connect(owner).authorizeRegistrar(otherAccount.address)
            ).to.emit(registry, "RegistrarAuthorized").withArgs(otherAccount.address);

            expect(await registry.isAuthorizedRegistrar(otherAccount.address)).to.equal(true);

            // Authorized registrar can now register
            const hash = ethers.keccak256(ethers.toUtf8Bytes("Authorized Report"));
            await expect(
                registry.connect(otherAccount).registerReport(hash)
            ).to.emit(registry, "ReportRegistered");
        });

        it("Should reject authorization from non-owners", async function () {
            await expect(
                registry.connect(unauthorizedAccount).authorizeRegistrar(otherAccount.address)
            ).to.be.revertedWith("Only owner can perform this action");
        });

        it("Should allow owner to revoke registrar authority", async function () {
            await registry.connect(owner).authorizeRegistrar(otherAccount.address);
            expect(await registry.isAuthorizedRegistrar(otherAccount.address)).to.equal(true);

            await expect(
                registry.connect(owner).revokeRegistrar(otherAccount.address)
            ).to.emit(registry, "RegistrarRevoked").withArgs(otherAccount.address);

            expect(await registry.isAuthorizedRegistrar(otherAccount.address)).to.equal(false);

            // Once revoked, registration reverts
            const hash = ethers.keccak256(ethers.toUtf8Bytes("Post Revocation"));
            await expect(
                registry.connect(otherAccount).registerReport(hash)
            ).to.be.revertedWith("Unauthorized registrar");
        });

        it("Should prevent revoking the contract owner", async function () {
            await expect(
                registry.connect(owner).revokeRegistrar(owner.address)
            ).to.be.revertedWith("Cannot revoke contract owner");
        });

        it("Should support ownership transfer", async function () {
            await expect(
                registry.connect(owner).transferOwnership(otherAccount.address)
            ).to.emit(registry, "OwnershipTransferred").withArgs(owner.address, otherAccount.address);

            expect(await registry.owner()).to.equal(otherAccount.address);
            expect(await registry.isAuthorizedRegistrar(otherAccount.address)).to.equal(true);
        });
    });

    // ────────────────────────────────────────────────
    //  6. Edge cases & Stress tests
    // ────────────────────────────────────────────────

    describe("Edge cases", function () {

        it("Should handle multiple sequential registrations", async function () {
            for (let i = 0; i < 10; i++) {
                const hash = ethers.keccak256(
                    ethers.toUtf8Bytes(`Report ${i}`)
                );
                await registry.registerReport(hash);
            }
            expect(await registry.reportCount()).to.equal(10);
        });

        it("Should set hashExists correctly", async function () {
            const hash = ethers.keccak256(
                ethers.toUtf8Bytes("Threat Report A")
            );

            expect(await registry.hashExists(hash)).to.equal(false);
            await registry.registerReport(hash);
            expect(await registry.hashExists(hash)).to.equal(true);
        });
    });
});
