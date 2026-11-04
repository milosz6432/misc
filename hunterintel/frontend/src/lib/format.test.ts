import { describe, expect, it } from "vitest";
import { bytes, defang, formatDate, pretty, timeAgo } from "./format";

describe("defang", () => {
  it("defangs network indicators", () => {
    expect(defang("https://evil.example.com/a", "url")).toBe("hxxps://evil[.]example[.]com/a");
    expect(defang("a@b.example", "email")).toBe("a[@]b[.]example");
    expect(defang("1.2.3.4", "ip")).toBe("1[.]2[.]3[.]4");
  });
  it("leaves hashes and ASNs alone", () => {
    expect(defang("abc123", "hash")).toBe("abc123");
    expect(defang("AS13335", "asn")).toBe("AS13335");
  });
});

describe("time", () => {
  const now = Date.parse("2026-11-04T12:00:00Z");
  it("renders relative times", () => {
    expect(timeAgo("2026-11-04T11:59:50Z", now)).toBe("just now");
    expect(timeAgo("2026-11-04T10:00:00Z", now)).toBe("2 h ago");
    expect(timeAgo("2026-10-04T12:00:00Z", now)).toBe("31 d ago");
    expect(timeAgo(null, now)).toBe("never");
  });
  it("formats ISO dates in UTC", () => {
    expect(formatDate("2026-11-04T12:34:56+00:00")).toBe("2026-11-04 12:34Z");
    expect(formatDate(undefined)).toBe("—");
  });
});

describe("misc", () => {
  it("formats bytes and labels", () => {
    expect(bytes(512)).toBe("512 B");
    expect(bytes(1536)).toBe("1.5 KiB");
    expect(pretty("dns.records")).toBe("dns records");
  });
});
