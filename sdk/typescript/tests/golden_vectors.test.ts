/**
 * Cross-language golden vector tests for JCS (RFC 8785) canonical hashing.
 *
 * These tests read `definitions/test_vectors/jcs/golden.json` from the repository
 * root and verify that a minimal TypeScript JCS implementation produces
 * the same SHA-256 hashes as the Rust `latchgate-core` crate.
 *
 * The vectors are the single source of truth for cross-SDK hash
 * compatibility. If this test fails, either:
 *   1. The golden vectors were changed without updating all SDKs, or
 *   2. The TypeScript JSON/crypto implementation diverged from JCS.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Minimal JCS canonicalization (RFC 8785)
// ---------------------------------------------------------------------------

/**
 * Recursively sort object keys and serialize to JSON without whitespace.
 *
 * This is a minimal JCS implementation sufficient for the golden vectors.
 * Full RFC 8785 compliance requires IEEE 754 number formatting — JS
 * `JSON.stringify` uses the spec-mandated ToString(Number) which matches
 * JCS for all I-JSON values (no NaN/Infinity).
 */
function jcsCanonicalise(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return "[" + value.map(jcsCanonicalise).join(",") + "]";
  }

  // Sort keys lexicographically (UTF-16 code unit order = JS default sort).
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries = sortedKeys.map(
    (k) => JSON.stringify(k) + ":" + jcsCanonicalise(obj[k]),
  );
  return "{" + entries.join(",") + "}";
}

async function sha256Hex(data: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(data),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

interface GoldenVector {
  description: string;
  input: unknown;
  canonical?: string;
  sha256: string;
}

// Resolve path relative to this test file: tests/ => sdk/typescript/ => sdk/ => repo root.
const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN_PATH = resolve(HERE, "..", "..", "..", "definitions", "test_vectors", "jcs", "golden.json");

const vectors: GoldenVector[] = JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as GoldenVector[];

describe("JCS golden vectors (cross-lang)", () => {
  it("golden.json is loadable and non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const [i, v] of vectors.entries()) {
    const label = `[${i}] ${v.description}`;

    if (v.canonical !== undefined) {
      it(`${label}: canonical form matches`, () => {
        expect(jcsCanonicalise(v.input)).toBe(v.canonical);
      });
    }

    it(`${label}: SHA-256 matches`, async () => {
      const canonical = jcsCanonicalise(v.input);
      const hash = `sha256:${await sha256Hex(canonical)}`;
      expect(hash).toBe(v.sha256);
    });
  }
});
