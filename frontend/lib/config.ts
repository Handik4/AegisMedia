import deployment from "./deployment.json";

// GenLayer Studio Next. Chain 61997 is served by studio-next.genlayer.com; the
// RPC and explorer are overridable per deployment through NEXT_PUBLIC_* vars.
export const CHAIN_ID = 61997;
export const CHAIN_ID_HEX = "0xf22d";
export const NETWORK_LABEL = "GenLayer Studio Next";
export const RPC_URL =
  process.env.NEXT_PUBLIC_GENLAYER_RPC_URL ?? "https://studio-next.genlayer.com/api";
export const EXPLORER_URL =
  process.env.NEXT_PUBLIC_GENLAYER_EXPLORER_URL ?? "https://explorer-studio-next.genlayer.com";
export const GITHUB_URL =
  process.env.NEXT_PUBLIC_GITHUB_URL ?? "https://github.com/Handik4/AegisMedia";

// The contract address comes from lib/deployment.json (written by
// scripts/deploy.py) unless NEXT_PUBLIC_AEGIS_CONTRACT_ADDRESS overrides it.
export const CONTRACT_ADDRESS: string =
  process.env.NEXT_PUBLIC_AEGIS_CONTRACT_ADDRESS || deployment.address || "";

export const IS_CONFIGURED = /^0x[0-9a-fA-F]{40}$/.test(CONTRACT_ADDRESS);

export const contractExplorerUrl = (address = CONTRACT_ADDRESS) =>
  `${EXPLORER_URL}/address/${address}`;
export const txExplorerUrl = (hash: string) => `${EXPLORER_URL}/tx/${hash}`;

// Protocol constants mirrored from contracts/aegis_media.py (also served live by
// get_config; these are only used for pre-flight form hints).
export const ATTO = 10n ** 18n;
export const MIN_STAKE_GEN = 5;
export const MIN_BOND_GEN = 0.5;
export const FEE_BPS = 300n;
export const HAMMING_THRESHOLD = 10;
