import type { Assurance, Observation } from "../api/types";

export interface Fact {
  label: string;
  value: string;
  assurance: Assurance;
  source: string;
  note?: string;
}

type Data = Record<string, unknown>;
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : typeof v === "number" ? String(v) : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strs = (v: unknown): string[] => arr(v).map((x) => String(x));
const obj = (v: unknown): Data => (v && typeof v === "object" && !Array.isArray(v) ? (v as Data) : {});

/**
 * Condense observations into the handful of facts an analyst wants at a glance. Each fact
 * keeps the assurance and source of the observation it came from.
 */
export function extractFacts(observations: Observation[]): Fact[] {
  const facts: Fact[] = [];
  for (const o of observations) {
    const d = o.data as Data;
    const add = (label: string, value: string | null | undefined, note?: string) => {
      if (value) facts.push({ label, value, assurance: o.assurance, source: o.provider, note });
    };
    switch (o.kind) {
      case "dns.records": {
        if (d.nxdomain) {
          add("Resolution", "NXDOMAIN — the name does not exist (per the configured resolvers)");
          break;
        }
        const r = obj(d.records);
        for (const t of ["A", "AAAA", "CNAME", "NS"]) if (arr(r[t]).length) add(`${t} records`, strs(r[t]).join(", "));
        if (arr(r.MX).length) add("MX", arr(r.MX).map((m) => `${str(obj(m).preference) ?? "?"} ${str(obj(m).exchange) ?? ""}`).join(", "));
        break;
      }
      case "dns.email_security": {
        const spf = obj(d.spf);
        const dmarc = obj(d.dmarc);
        add("SPF", str(spf.policy) ? `${str(spf.policy)}` : "no SPF record");
        add("DMARC", str(dmarc.policy) ? `p=${str(dmarc.policy)}` : "no DMARC record");
        break;
      }
      case "dns.ptr": {
        const ptr = strs(d.ptr);
        add("Reverse DNS", ptr.length ? ptr.join(", ") : "no PTR record", ptr.length && !d.fcrdns ? "Not forward-confirmed: a PTR is set by the address owner and can claim any name." : undefined);
        if (ptr.length && d.fcrdns) add("Forward-confirmed", "yes — the name resolves back to this address");
        break;
      }
      case "rdap.domain": {
        const registrar = obj(d.registrar);
        add("Registered", str(d.registered)?.slice(0, 10) ?? null, typeof d.age_days === "number" ? `${d.age_days} days ago` : undefined);
        add("Expires", str(d.expires)?.slice(0, 10) ?? null);
        add("Registrar", str(registrar.name));
        if (arr(d.status).length) add("Registry status", strs(d.status).join(", "));
        break;
      }
      case "rdap.network": {
        add("Network", [str(d.name), str(d.handle)].filter(Boolean).join(" · "));
        add("Allocation", strs(d.cidrs).join(", "));
        add("Owner", strs(d.owner_organisations).join(", "));
        add("Registration country", str(d.registration_country), str(d.accuracy_note) ?? undefined);
        break;
      }
      case "rdap.autnum":
        add("AS registration", [str(d.name), str(d.handle)].filter(Boolean).join(" · "));
        add("Registration country", str(d.registration_country));
        break;
      case "network.asn":
        if (arr(d.asns).length) {
          add("Origin AS", strs(d.asns).map((a) => `AS${a}`).join(", ") + (str(d.as_name) ? ` — ${str(d.as_name)}` : ""));
          add("Prefix", str(d.prefix));
          add("Registry country", str(d.registry_country), str(d.caveat) ?? undefined);
        } else if (d.asn) {
          add("Origin AS", `AS${str(d.asn)}${str(d.as_owner) ? ` — ${str(d.as_owner)}` : ""}`);
          add("Network", str(d.network));
          add("Country (estimate)", str(d.country), str(d.caveat) ?? undefined);
        }
        break;
      case "network.asn_name":
        add("AS name", str(d.name), str(d.caveat) ?? undefined);
        break;
      case "geo.location":
        add(
          "Location (estimate)",
          [str(d.city), str(d.country)].filter(Boolean).join(", ") || null,
          str(d.accuracy_note) ?? undefined,
        );
        break;
      case "file.info":
        add("File type", str(d.file_type) ?? str(d.type_tag));
        add("Size", str(d.size) ? `${str(d.size)} bytes` : null);
        add("Family / signature", str(d.signature) ?? str(d.suggested_threat_label));
        add("Name", str(d.file_name) ?? str(d.meaningful_name));
        add("Delivery", str(d.delivery_method));
        break;
      case "local.url_components":
        add("Host", `${str(d.host)} (${str(d.host_kind)})`);
        add("Registrable domain", str(d.registered_domain));
        add("Path", `${str(d.path)}${d.query ? "?" + str(d.query) : ""}`);
        break;
      case "ct.certificates":
        add("Certificates (CT)", `${str(d.unique_certificates)} certificate(s), ${arr(d.subdomains).length} distinct name(s)`, str(d.caveat) ?? undefined);
        break;
      case "ct.certificate":
        add("Certificate", `${str(d.common_name)} — issued by ${str(d.issuer)}`);
        add("Validity", `${str(d.not_before)?.slice(0, 10)} → ${str(d.not_after)?.slice(0, 10)}`);
        break;
      case "abuse.reports":
        add("Abuse reports", `${str(d.total_reports)} in ${str(d.window_days)} days (confidence ${str(d.abuse_confidence_score)}%)`, str(d.caveat) ?? undefined);
        add("Usage / ISP", [str(d.usage_type), str(d.isp)].filter(Boolean).join(" · "));
        break;
      case "otx.pulses":
        add("OTX pulses", String(d.pulse_count), str(d.caveat) ?? undefined);
        if (arr(d.malware_families).length) add("Malware families (OTX)", strs(d.malware_families).join(", "));
        if (arr(d.adversaries).length) add("Adversaries (OTX)", strs(d.adversaries).join(", "));
        break;
      case "urlhaus.listing":
        add("URLhaus", `${str(d.url_status) ?? "listed"}${str(d.threat) ? ` · ${str(d.threat)}` : ""}`);
        break;
      case "urlhaus.host":
        add("URLhaus", `${str(d.url_count)} listed URL(s)`);
        break;
      case "probe.redirect_chain":
        add("Redirect chain", `${arr(d.hops).length} hop(s) → ${str(d.final_url) ?? str(d.stopped_reason) ?? "incomplete"}`);
        break;
      case "reputation": {
        const s = obj(d.signal);
        add(`Reputation`, str(s.label));
        break;
      }
      default:
        break;
    }
  }
  return facts;
}
