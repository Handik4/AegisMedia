import { keccak256, toBytes } from "viem";
import { CHAIN_ID } from "./config";

export interface AnnouncementPayload {
  entityId: bigint;
  contentUri: string;
  sha256: string; // 64 hex
  phash: string; // 16 hex
  metadataDigest: string; // 64 hex
  timestamp: bigint;
}

/** EIP-712 typed data matching contracts/aegis_media.py (type string must stay identical). */
export function announcementTypedData(verifyingContract: string, p: AnnouncementPayload) {
  return {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      Announcement: [
        { name: "entityId", type: "uint256" },
        { name: "contentUriHash", type: "bytes32" },
        { name: "sha256Hash", type: "bytes32" },
        { name: "phash", type: "uint64" },
        { name: "metadataDigest", type: "bytes32" },
        { name: "timestamp", type: "uint256" },
      ],
    },
    primaryType: "Announcement" as const,
    domain: { name: "AegisMedia", version: "1", chainId: CHAIN_ID, verifyingContract },
    message: {
      entityId: p.entityId.toString(),
      contentUriHash: keccak256(toBytes(p.contentUri)),
      sha256Hash: `0x${p.sha256}`,
      phash: BigInt(`0x${p.phash}`).toString(),
      metadataDigest: `0x${p.metadataDigest}`,
      timestamp: p.timestamp.toString(),
    },
  };
}

/** Ask the injected wallet to sign the announcement (eth_signTypedData_v4). */
export async function signAnnouncement(
  account: string,
  verifyingContract: string,
  payload: AnnouncementPayload
): Promise<string> {
  const eth = (window as unknown as { ethereum?: { request(a: { method: string; params: unknown[] }): Promise<unknown> } })
    .ethereum;
  if (!eth) throw new Error("No injected wallet detected.");
  const data = announcementTypedData(verifyingContract, payload);
  return (await eth.request({
    method: "eth_signTypedData_v4",
    params: [account, JSON.stringify(data)],
  })) as string;
}
