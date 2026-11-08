/**
 * CyberShield AI — Next.js API Route for Blockchain Integration
 * =============================================================
 * Route: POST /api/blockchain
 *
 * Supported Actions:
 *   - "hash":     Compute deterministic report_hash and report_id for a UnifiedThreatReport.
 *   - "verify":   Verify report integrity against the on-chain ThreatReportRegistry.
 *   - "register": Register report hash on-chain (requires RPC & private key).
 */

import {
  computeReportHash,
  computeReportId,
  normalizeThreatReport,
  validateThreatReport,
  UnifiedThreatReport,
} from "../../../lib/blockchain/threatReport";
import { ethers } from "ethers";

// Default contract ABI for registration and verification
const REGISTRY_ABI = [
  "function registerReport(bytes32 reportHash) external returns (bytes32)",
  "function verifyReport(bytes32 reportId, bytes32 reportHash) external view returns (bool)",
  "function getReport(bytes32 reportId) external view returns (bytes32, bytes32, address, uint256)",
  "function reportCount() external view returns (uint256)",
];

interface BlockchainRequestBody {
  action: "hash" | "verify" | "register";
  report: UnifiedThreatReport;
  contract_address?: string;
  rpc_url?: string;
}

export async function POST(req: Request) {
  try {
    const body: BlockchainRequestBody = await req.json();

    if (!body || !body.action || !body.report) {
      return Response.json(
        {
          error: "Invalid request payload. Must provide 'action' ('hash' | 'verify' | 'register') and 'report'.",
        },
        { status: 400 }
      );
    }

    // 1. Validate report schema
    let validatedReport: UnifiedThreatReport;
    try {
      validatedReport = validateThreatReport(body.report);
    } catch (valErr: any) {
      return Response.json(
        {
          error: `Schema validation failed: ${valErr.message}`,
          action: body.action,
        },
        { status: 400 }
      );
    }

    // 2. Compute canonical hash & deterministic ID
    const reportHash = computeReportHash(validatedReport);
    const reportId = computeReportId(reportHash);

    // Action: Hash only
    if (body.action === "hash") {
      return Response.json({
        report_id: reportId,
        report_hash: reportHash,
        status: "hashed",
        normalized_report_id: validatedReport.report_id,
      });
    }

    // Provider & Contract configuration
    const rpcUrl =
      body.rpc_url ||
      process.env.BLOCKCHAIN_RPC_URL ||
      "http://127.0.0.1:8545";

    const contractAddress =
      body.contract_address ||
      process.env.REGISTRY_CONTRACT_ADDRESS ||
      "0x5FbDB2315678afecb367f032d93F642f64180aa3";

    const provider = new ethers.JsonRpcProvider(rpcUrl);

    // Action: Verify
    if (body.action === "verify") {
      try {
        const contract = new ethers.Contract(contractAddress, REGISTRY_ABI, provider);
        const verified = await contract.verifyReport(reportId, reportHash);

        return Response.json({
          report_id: reportId,
          report_hash: reportHash,
          verified: Boolean(verified),
          contract_address: contractAddress,
          rpc_url: rpcUrl,
        });
      } catch (rpcErr: any) {
        return Response.json(
          {
            report_id: reportId,
            report_hash: reportHash,
            verified: false,
            error: `RPC verification failed: ${rpcErr.message}`,
            contract_address: contractAddress,
          },
          { status: 502 }
        );
      }
    }

    // Action: Register
    if (body.action === "register") {
      const privateKey =
        process.env.BLOCKCHAIN_PRIVATE_KEY ||
        process.env.DEPLOYER_PRIVATE_KEY;

      if (!privateKey) {
        return Response.json(
          {
            error: "No private key configured on server. Set BLOCKCHAIN_PRIVATE_KEY to sign transactions.",
            report_id: reportId,
            report_hash: reportHash,
          },
          { status: 500 }
        );
      }

      try {
        const wallet = new ethers.Wallet(privateKey, provider);
        const contract = new ethers.Contract(contractAddress, REGISTRY_ABI, wallet);

        const tx = await contract.registerReport(reportHash);
        const receipt = await tx.wait();

        if (receipt.status !== 1) {
          return Response.json(
            {
              error: `Transaction reverted on-chain (status=${receipt.status})`,
              tx_hash: receipt.hash,
              report_id: reportId,
              report_hash: reportHash,
            },
            { status: 500 }
          );
        }

        return Response.json({
          report_id: reportId,
          report_hash: reportHash,
          tx_hash: receipt.hash,
          block_number: receipt.blockNumber,
          status: "registered",
          contract_address: contractAddress,
        });
      } catch (txErr: any) {
        return Response.json(
          {
            error: `On-chain registration failed: ${txErr.message}`,
            report_id: reportId,
            report_hash: reportHash,
          },
          { status: 500 }
        );
      }
    }

    return Response.json(
      { error: `Unsupported action '${body.action}'` },
      { status: 400 }
    );
  } catch (err: any) {
    return Response.json(
      { error: `Internal server error: ${err.message}` },
      { status: 500 }
    );
  }
}
