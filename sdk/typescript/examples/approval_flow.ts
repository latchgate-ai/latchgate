/**
 * LatchGate approval flow — agent submits, operator approves, gate executes.
 *
 * Demonstrates the full approval lifecycle:
 *   1. Agent submits a high-risk action => gate holds it (HTTP 202)
 *   2. Operator loads credentials and approves via DPoP-authenticated admin API
 *   3. Gate executes the stored plan and returns a signed receipt
 *
 * The agent and operator are separate roles with separate authentication.
 * In production the operator is a human or automated review system on a
 * different machine. This example plays both roles from a single script.
 *
 * Requires a running gate:
 *   latchgate up
 *
 * Run:
 *   npx tsx examples/approval_flow.ts
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { Agent, fetch as undiciFetch } from "undici";

import {
  LatchGateClient,
  LatchGateApprovalRequired,
  LatchGateDenied,
} from "../src/index.js";

// Operator DPoP auth uses internal crypto primitives. These are not part of
// the agent SDK's public surface — operator auth is a separate concern that
// runs on the admin socket in production.
import { DPoPKeyPair, computeAth } from "../src/crypto.js";

/** Server's default public_base_url — used for DPoP htu construction. */
const PUBLIC_BASE_URL = "http://localhost:3000";

// -- Helpers ----------------------------------------------------------------

function abort(msg: string): never {
  console.error(`  error: ${msg}`);
  process.exit(1);
}

// -- Socket paths -----------------------------------------------------------

/**
 * Resolve the admin UDS socket path.
 *
 * Mirrors the server's default_admin_uds_path so that latchgate up
 * and this example agree without manual configuration.
 */
function defaultAdminSocketPath(): string {
  const xdg = process.env["XDG_RUNTIME_DIR"] ?? "";
  if (xdg) return `${xdg}/latchgate/gate-admin.sock`;
  const uid = process.getuid?.() ?? 0;
  return `/tmp/latchgate-${uid}/gate-admin.sock`;
}

// -- Operator credential discovery ------------------------------------------

interface OperatorCredentials {
  name: string;
  apiKey: string;
  keypair: DPoPKeyPair;
}

/**
 * Walk up from cwd to find the .latchgate project directory.
 */
function findRepoRoot(): string {
  let dir = process.cwd();
  while (true) {
    if (existsSync(join(dir, ".latchgate", "latchgate.toml"))) {
      return dir;
    }
    const parent = join(dir, "..");
    if (parent === dir) {
      abort(
        "cannot find .latchgate/latchgate.toml — " +
          "run 'latchgate up' from the repo root first",
      );
    }
    dir = parent;
  }
}

/**
 * Parse the first operator_credentials entry from a latchgate.toml file.
 *
 * Uses line-by-line parsing to avoid a TOML library dependency.
 */
function parseOperatorFromToml(
  tomlText: string,
): { name: string; apiKey: string } {
  const sectionRe = /^\[operator_credentials\.(\w+)\]/;
  const kvRe = /^\s*(\w+)\s*=\s*"([^"]+)"/;

  let name: string | null = null;
  let apiKey: string | null = null;
  let inSection = false;

  for (const line of tomlText.split("\n")) {
    const trimmed = line.trim();

    if (trimmed.startsWith("[")) {
      if (inSection) break;
      const m = sectionRe.exec(trimmed);
      if (m) {
        name = m[1]!;
        inSection = true;
      }
      continue;
    }

    if (!inSection) continue;

    const kv = kvRe.exec(trimmed);
    if (kv && kv[1] === "api_key") {
      apiKey = kv[2]!;
    }
  }

  if (!name || !apiKey) {
    abort("no [operator_credentials.*] with api_key in latchgate.toml");
  }

  return { name, apiKey };
}

async function loadOperatorCredentials(
  repoRoot: string,
): Promise<OperatorCredentials> {
  const tomlPath = join(repoRoot, ".latchgate", "latchgate.toml");
  const tomlText = readFileSync(tomlPath, "utf-8");
  const { name, apiKey } = parseOperatorFromToml(tomlText);

  const pemPath = join(repoRoot, ".latchgate", "operators", `${name}.pem`);
  if (!existsSync(pemPath)) {
    abort(`operator PEM not found: ${pemPath}`);
  }

  const pem = readFileSync(pemPath, "utf-8");
  const keypair = await DPoPKeyPair.fromPem(pem);

  return { name, apiKey, keypair };
}

// -- Operator approval via admin API ----------------------------------------

/**
 * Approve a pending action via the admin API with DPoP auth.
 *
 * Connects via the admin UDS socket — the admin API is not exposed on the
 * client socket.
 */
async function approve(
  approvalId: string,
  apiKey: string,
  keypair: DPoPKeyPair,
): Promise<Record<string, unknown>> {
  const path = `/v1/approvals/${approvalId}/approve`;
  const htu = `${PUBLIC_BASE_URL}${path}`;
  const ath = await computeAth(apiKey);
  const proof = await keypair.signProof("POST", htu, ath);

  const dispatcher = new Agent({
    connect: { socketPath: defaultAdminSocketPath() },
  });

  const resp = await (undiciFetch as unknown as (
    url: string,
    init: Record<string, unknown>,
  ) => Promise<Response>)(`http://localhost${path}`, {
    method: "POST",
    headers: {
      Authorization: `DPoP ${apiKey}`,
      DPoP: proof,
      "Content-Type": "application/json",
    },
    dispatcher,
  });

  const body = (await resp.json()) as Record<string, unknown>;

  if (!resp.ok) {
    await (dispatcher as Agent).close();
    return { _error: true, status: resp.status, ...body };
  }

  await (dispatcher as Agent).close();
  return body;
}

// -- Agent submission -------------------------------------------------------

/**
 * Submit http_sensitive_read as an agent. Returns the approval_id.
 *
 * Exits early if the policy auto-allows or denies outright, since those
 * paths don't involve the approval lifecycle.
 */
async function submitAsAgent(): Promise<string> {
  const client = new LatchGateClient({ publicBaseUrl: PUBLIC_BASE_URL });

  try {
    await client.connect({ agentId: "approval-flow-example" });
    console.log("  lease acquired");

    const result = await client.execute("http_sensitive_read", {
      url: "https://httpbin.org/get",
    });

    // Policy auto-allowed — dev-mode default may vary.
    console.log(`  auto-allowed — receipt: ${result.receiptId}`);
    console.log();
    console.log("  policy did not require approval for this action.");
    console.log("  check policies/data.json to enable approval holds.");
    process.exit(0);
  } catch (err) {
    if (err instanceof LatchGateApprovalRequired) {
      console.log(`  held for approval — approval_id: ${err.approvalId}`);
      return err.approvalId;
    }
    if (err instanceof LatchGateDenied) {
      console.log(`  denied: ${err.reason}`);
      console.log(
        "  the action was denied outright — no approval path available.",
      );
      process.exit(0);
    }
    throw err;
  } finally {
    await client.close();
  }
}

// -- Main -------------------------------------------------------------------

async function main(): Promise<void> {
  // -- Discover operator credentials before we start ----------------------
  const repoRoot = findRepoRoot();
  const { apiKey, keypair } = await loadOperatorCredentials(repoRoot);
  console.log("  operator credentials loaded");

  // -- Step 1: Agent submits a high-risk action ---------------------------
  console.log();
  console.log("  step 1: agent submits http_sensitive_read (risk: high)");

  const approvalId = await submitAsAgent();

  // -- Step 2: Operator approves ------------------------------------------
  console.log();
  console.log(`  step 2: operator approves ${approvalId}`);

  const body = await approve(approvalId, apiKey, keypair);

  if (body._error) {
    const denyReason = String(body.deny_reason ?? body.error ?? "unknown");
    const isSecretsIssue = denyReason.toLowerCase().includes("secrets");

    if (isSecretsIssue) {
      console.log("  approved — but execution requires secrets (SOPS not configured)");
      console.log();
      console.log("  ✓ The approval lifecycle completed successfully:");
      console.log("    agent submitted → gate held → operator approved");
      console.log();
      console.log("  The action declares required secrets that need SOPS setup.");
      console.log("  See: https://latchgate-docs.pages.dev/secrets/");
    } else {
      console.log(`  approval failed (HTTP ${body.status}): ${denyReason}`);
    }
    return;
  }

  const receiptId = body.receipt_id as string | undefined;
  const grantId = body.grant_id as string | undefined;

  console.log("  approved and executed");
  if (receiptId) console.log(`  receipt:  ${receiptId}`);
  if (grantId) console.log(`  grant:    ${grantId}`);

  // -- Done ---------------------------------------------------------------
  console.log();
  console.log("  the agent submitted a high-risk action.");
  console.log("  the gate held it until an operator approved.");
  console.log(
    "  the gate then executed the stored plan — not a re-derived one.",
  );
  console.log("  the signed receipt proves what happened and when.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
