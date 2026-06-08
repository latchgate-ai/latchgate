import { describe, it, expect } from "vitest";
import { DPoPKeyPair, computeAth, normalizeHtu } from "../src/crypto.js";

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

describe("DPoPKeyPair.generate", () => {
  it("returns EC P-256 JWK", async () => {
    const kp = await DPoPKeyPair.generate();
    expect(kp.jwk.kty).toBe("EC");
    expect(kp.jwk.crv).toBe("P-256");
    expect(typeof kp.jwk.x).toBe("string");
    expect(typeof kp.jwk.y).toBe("string");
  });

  it("x and y are base64url without padding", async () => {
    const kp = await DPoPKeyPair.generate();
    for (const coord of [kp.jwk.x, kp.jwk.y]) {
      expect(coord).not.toContain("=");
      expect(coord).not.toContain("+");
      expect(coord).not.toContain("/");
    }
  });

  it("x and y are 32 bytes", async () => {
    const kp = await DPoPKeyPair.generate();
    for (const coord of [kp.jwk.x, kp.jwk.y]) {
      const raw = Uint8Array.from(atob(coord.replaceAll("-", "+").replaceAll("_", "/")), (c) =>
        c.charCodeAt(0),
      );
      expect(raw.byteLength).toBe(32);
    }
  });

  it("two keypairs are distinct", async () => {
    const kp1 = await DPoPKeyPair.generate();
    const kp2 = await DPoPKeyPair.generate();
    expect(kp1.jwk.x).not.toBe(kp2.jwk.x);
  });
});

// ---------------------------------------------------------------------------
// DPoP proof structure
// ---------------------------------------------------------------------------

function decodeJwtPart(b64: string): Record<string, unknown> {
  const padded = b64 + "=".repeat(-b64.length & 3);
  return JSON.parse(atob(padded.replaceAll("-", "+").replaceAll("_", "/"))) as Record<string, unknown>;
}

describe("DPoPKeyPair.signProof", () => {
  it("returns a 3-part JWT", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("POST", "http://localhost/v1/leases", "ath");
    expect(proof.split(".")).toHaveLength(3);
  });

  it("header typ is dpop+jwt and alg is ES256", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("POST", "http://localhost/v1/leases", "ath");
    const header = decodeJwtPart(proof.split(".")[0]!);
    expect(header["typ"]).toBe("dpop+jwt");
    expect(header["alg"]).toBe("ES256");
  });

  it("header jwk matches keypair public key", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("POST", "http://localhost/v1/leases", "ath");
    const header = decodeJwtPart(proof.split(".")[0]!);
    const jwk = header["jwk"] as Record<string, string>;
    expect(jwk["kty"]).toBe("EC");
    expect(jwk["crv"]).toBe("P-256");
    expect(jwk["x"]).toBe(kp.jwk.x);
    expect(jwk["y"]).toBe(kp.jwk.y);
  });

  it("payload htm is uppercased", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("post", "http://localhost/v1/leases", "ath");
    const payload = decodeJwtPart(proof.split(".")[1]!);
    expect(payload["htm"]).toBe("POST");
  });

  it("payload contains required claims", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("POST", "http://localhost/v1/leases", "my-ath");
    const payload = decodeJwtPart(proof.split(".")[1]!);
    expect(payload).toHaveProperty("jti");
    expect(payload).toHaveProperty("htm");
    expect(payload).toHaveProperty("htu");
    expect(payload).toHaveProperty("iat");
    expect(payload["ath"]).toBe("my-ath");
  });

  it("jti is unique per call", async () => {
    const kp = await DPoPKeyPair.generate();
    const p1 = await kp.signProof("POST", "http://localhost/v1/leases", "ath");
    const p2 = await kp.signProof("POST", "http://localhost/v1/leases", "ath");
    const jti1 = decodeJwtPart(p1.split(".")[1]!)["jti"];
    const jti2 = decodeJwtPart(p2.split(".")[1]!)["jti"];
    expect(jti1).not.toBe(jti2);
  });

  it("signature is 64 bytes (r||s)", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("POST", "http://localhost/v1/leases", "ath");
    const sigB64 = proof.split(".")[2]!;
    const raw = Uint8Array.from(
      atob(sigB64.replaceAll("-", "+").replaceAll("_", "/")),
      (c) => c.charCodeAt(0),
    );
    expect(raw.byteLength).toBe(64);
  });

  it("signature is verifiable with the public key from the JWK", async () => {
    const kp = await DPoPKeyPair.generate();
    const proof = await kp.signProof("POST", "http://localhost/v1/actions/test/execute", "ath");
    const [headerB64, payloadB64, sigB64] = proof.split(".") as [string, string, string];

    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const rawSig = Uint8Array.from(
      atob(sigB64.replaceAll("-", "+").replaceAll("_", "/")),
      (c) => c.charCodeAt(0),
    );

    const pubKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: kp.jwk.x, y: kp.jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pubKey,
      rawSig,
      signingInput,
    );
    expect(valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeAth
// ---------------------------------------------------------------------------

describe("computeAth", () => {
  it("is SHA-256 base64url of the token", async () => {
    const token = "eyJhbGciOiJFUzI1NiJ9.test.sig";
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    expect(await computeAth(token)).toBe(expected);
  });

  it("has no padding", async () => {
    expect(await computeAth("some.lease.jwt")).not.toContain("=");
  });

  it("differs for different tokens", async () => {
    expect(await computeAth("token-a")).not.toBe(await computeAth("token-b"));
  });

  it("is deterministic", async () => {
    const token = "lease.jwt.value";
    expect(await computeAth(token)).toBe(await computeAth(token));
  });
});

// ---------------------------------------------------------------------------
// normalizeHtu — mirrors server vectors from
// crates/latchgate-auth/src/dpop/mod.rs
// ---------------------------------------------------------------------------

describe("normalizeHtu", () => {
  it("strips query string", () => {
    expect(normalizeHtu("https://host.example/path?q=1&r=2")).toBe(
      "https://host.example/path",
    );
  });

  it("strips fragment", () => {
    expect(normalizeHtu("https://host.example/path#section")).toBe(
      "https://host.example/path",
    );
  });

  it("strips query and fragment", () => {
    expect(normalizeHtu("https://host.example/path?q=1#frag")).toBe(
      "https://host.example/path",
    );
  });

  it("lowercases scheme and host", () => {
    expect(normalizeHtu("HTTPS://HOST.EXAMPLE/Path")).toBe(
      "https://host.example/Path",
    );
  });

  it("removes default https:443 port", () => {
    expect(normalizeHtu("https://host.example:443/api")).toBe(
      normalizeHtu("https://host.example/api"),
    );
  });

  it("removes default http:80 port", () => {
    expect(normalizeHtu("http://host.example:80/api")).toBe(
      normalizeHtu("http://host.example/api"),
    );
  });

  it("keeps non-default port", () => {
    expect(normalizeHtu("https://host.example:8443/api")).toBe(
      "https://host.example:8443/api",
    );
  });

  it("without path defaults to slash", () => {
    expect(normalizeHtu("https://host.example")).toBe("https://host.example/");
  });

  it("no scheme returns as-is", () => {
    expect(normalizeHtu("host.example/path")).toBe("host.example/path");
  });

  it("preserves percent-encoding in path", () => {
    expect(normalizeHtu("https://host.example/path%2Fsegment")).toBe(
      "https://host.example/path%2Fsegment",
    );
  });

  it("preserves path case", () => {
    expect(
      normalizeHtu("http://localhost:3000/v1/actions/Http_Fetch/execute"),
    ).toBe("http://localhost:3000/v1/actions/Http_Fetch/execute");
  });

  it("typical gate URL is unchanged", () => {
    expect(
      normalizeHtu("http://localhost:3000/v1/actions/http_fetch/execute"),
    ).toBe("http://localhost:3000/v1/actions/http_fetch/execute");
  });
});
