"""CyberShield AI — Live EVM Verification Script

Executes real on-chain transaction submission, receipt validation, verification,
duplicate rejection, and tamper detection against local Hardhat node.
"""

from app.services.report_generator import assemble_unified_threat_report
from app.services.blockchain import (
    BlockchainService,
    BlockchainTransactionError,
    threat_report_to_canonical_blockchain_dict,
)
from app.schemas.common import ScanType

def run_live_evm_checks():
    print("=== LIVE EVM INTEGRATION CHECK ===")
    svc = BlockchainService(
        rpc_url="http://127.0.0.1:8545",
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3"
    )
    print(f"Connected to node: {svc.rpc_url}")
    print(f"Contract: {svc.contract_address}")
    print(f"Signer: {svc.account}")

    # 1. Generate real report via Member 1
    m1_report = assemble_unified_threat_report(
        target="https://live-evm-test.cybershield.ai",
        target_type=ScanType.URL
    )
    canonical_dict = threat_report_to_canonical_blockchain_dict(m1_report)
    print(f"Generated Member 1 report: {m1_report.scan_id}")

    # 2. Register on live EVM
    reg_res = svc.register_report(canonical_dict)
    print(f"1. Registration: SUCCESS (tx: {reg_res['tx_hash']}, block: {reg_res['block_number']}, gas: {reg_res['gas_used']})")
    assert reg_res["status"] == "confirmed"

    # 3. Verify on live EVM
    ver_res = svc.verify_report(canonical_dict)
    print(f"2. Verification: {ver_res['verified']} (expected: True)")
    assert ver_res["verified"] is True

    # 4. Duplicate rejection test
    duplicate_rejected = False
    try:
        svc.register_report(canonical_dict)
    except BlockchainTransactionError as e:
        duplicate_rejected = True
        print(f"3. Duplicate rejection: SUCCESS (reverted as expected: {e})")
    assert duplicate_rejected, "Duplicate registration did not revert"

    # 5. Tampered report verification test
    tampered = dict(canonical_dict)
    tampered["confidence_score"] = 99
    ver_tampered = svc.verify_report(tampered)
    print(f"4. Tamper detection: verified={ver_tampered['verified']} (expected: False)")
    assert ver_tampered["verified"] is False

    print(f"Total reports on chain: {svc.report_count()}")
    print("=== ALL LIVE EVM CHECKS PASSED ===")

if __name__ == "__main__":
    run_live_evm_checks()

