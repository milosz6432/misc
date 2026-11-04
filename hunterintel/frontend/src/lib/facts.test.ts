import { describe, expect, it } from "vitest";
import type { Observation } from "../api/types";
import { extractFacts } from "./facts";

const obs = (kind: string, provider: string, assurance: Observation["assurance"], data: Record<string, unknown>): Observation => ({
  id: 1,
  indicator_id: 1,
  provider,
  kind,
  assurance,
  title: kind,
  summary: null,
  data,
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
  seen_count: 1,
});

describe("extractFacts", () => {
  it("keeps assurance and source on every fact", () => {
    const facts = extractFacts([
      obs("dns.records", "dns", "verified", { records: { A: ["198.51.100.1"], MX: [{ preference: 10, exchange: "mx.example.net" }] } }),
      obs("network.asn", "cymru", "provider_claim", { asns: [64500], prefix: "198.51.100.0/24", registry_country: "US", as_name: "EXAMPLE-AS", caveat: "RIR country" }),
    ]);
    const a = facts.find((f) => f.label === "A records");
    expect(a).toMatchObject({ value: "198.51.100.1", assurance: "verified", source: "dns" });
    expect(facts.find((f) => f.label === "MX")?.value).toBe("10 mx.example.net");
    const asn = facts.find((f) => f.label === "Origin AS");
    expect(asn).toMatchObject({ assurance: "provider_claim", source: "cymru" });
    expect(asn?.value).toContain("AS64500");
    expect(facts.find((f) => f.label === "Registry country")?.note).toBe("RIR country");
  });

  it("reports NXDOMAIN as a resolver-relative fact, not as an absolute", () => {
    const f = extractFacts([obs("dns.records", "dns", "verified", { nxdomain: true, records: {} })]);
    expect(f[0]?.value).toMatch(/per the configured resolvers/);
  });

  it("flags unconfirmed reverse DNS", () => {
    const f = extractFacts([obs("dns.ptr", "dns", "verified", { ptr: ["host.example.net"], fcrdns: false })]);
    expect(f[0]?.note).toMatch(/not forward-confirmed/i);
  });

  it("ignores unknown kinds and tolerates missing fields", () => {
    expect(extractFacts([obs("something.new", "x", "inferred", { a: 1 })])).toEqual([]);
    expect(() => extractFacts([obs("rdap.domain", "rdap", "verified", {})])).not.toThrow();
  });
});
