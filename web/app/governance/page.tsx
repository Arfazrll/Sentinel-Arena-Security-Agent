"use client";

import Link from "next/link";
import { CheckCircle2, Fingerprint, Gauge, Hash, Lock, OctagonX, ScrollText, ShieldCheck, Swords, Target, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { useFetch } from "@/lib/hooks";
import { dateTime, shortHash } from "@/lib/format";
import { Card, ErrorBanner, PageHead, Skeleton, Stat, StatusPill } from "@/components/ui";

const INVARIANTS = [
  { icon: <Fingerprint size={16} />, title: "Authorization gate before anything", body: "No request reaches a target until ownership of that exact host is proven with a per-user token (DNS TXT, well-known file or meta tag). Never a checkbox.", where: "authz.gate.AuthorizationGate" },
  { icon: <ShieldCheck size={16} />, title: "Non-destructive only", body: "Red detects and safely validates. It never crashes, floods, defaces or exfiltrates real data. The action vocabulary has no destructive verb.", where: "engine.actions.RED_ACTIONS" },
  { icon: <Target size={16} />, title: "Sandbox-only demos and CI", body: "Demos, tests and CI hit only the bundled vulnerable app on 127.0.0.1 or a self-hosted lab like Juice Shop.", where: "range/" },
  { icon: <Lock size={16} />, title: "No 'attack any URL' mode", body: "The target input stays inert until the gate passes for that host and scope. Scope is enforced on every single request.", where: "detect.client.GatedHttpClient" },
  { icon: <XCircle size={16} />, title: "No weaponized chains", body: "Red techniques are a curated detection set, run only against owned or sandbox targets. Blue has a whitelist and no shell.", where: "engine.actions.BLUE_ACTIONS" },
  { icon: <Hash size={16} />, title: "Tamper-evident audit trail", body: "Every gate decision is appended with the user, scope fingerprint, timestamp and a SHA-256 hash chain. The API offers no way to delete one.", where: "authz.audit.AuditLog" },
  { icon: <OctagonX size={16} />, title: "Kill switch, rate caps, staging first", body: "One control halts all agents instantly, from the CLI, API or the arena's emergency stop. Rate caps and staging-first scope are mandatory.", where: "engine.killswitch.KillSwitch" },
];

const FLOW = [
  { t: "Challenge issued", d: "The gate mints an HMAC token bound to the user and host." },
  { t: "Token published", d: "The target serves it at /.well-known/sentinel-arena.txt." },
  { t: "Ownership verified", d: "The gate fetches it from the real host and compares in constant time." },
  { t: "Scope signed", d: "Hosts, paths, rate cap, environment and time window are fingerprinted." },
  { t: "Gated requests", d: "Every red request is checked against scope before it leaves." },
  { t: "Audit appended", d: "Allow and deny decisions are hash-chained to the log." },
];

export default function GovernancePage() {
  const eng = useFetch(() => api.engagements());
  const latest = (eng.data || []).find((e) => e.status !== "running" && e.result && !e.result.error);
  const res = useFetch(() => (latest ? api.result(latest.id) : Promise.resolve(null)), [latest?.id]);
  const audit = useFetch(() => (latest ? api.audit(latest.id) : Promise.resolve(null)), [latest?.id]);
  const m = res.data?.meta;

  return (
    <>
      <PageHead
        title="Trust & safety"
        sub="Sentinel Arena is built so it can't be pointed at someone else's system. These seven controls are hard invariants, each backed by tests and a dedicated CI gate."
        actions={<Link href="/arena" className="btn primary"><Swords size={14} /> Run an authorized engagement</Link>}
      />
      {eng.error && <ErrorBanner error={eng.error} onRetry={eng.reload} />}

      <Card title="How a run is authorized" sub="Ownership is proven, not claimed">
        <div className="flow-steps">
          {FLOW.map((f, i) => (
            <div className="flow-step" key={f.t}>
              <div className="fs-n">STEP {i + 1}</div>
              <div className="fs-t">{f.t}</div>
              <div className="fs-d">{f.d}</div>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid g4" style={{ marginTop: 14 }}>
        {audit.loading && latest ? (
          [0, 1, 2, 3].map((i) => <Skeleton key={i} h={100} />)
        ) : latest && audit.data && m ? (
          <>
            <Stat icon={<ScrollText size={13} />} label="Latest audit chain" value={audit.data.verified ? "Intact" : "Broken"} tone={audit.data.verified ? "good" : "critical"} foot={<Link href={`/engagements/${latest.id}?tab=audit`} className="text-2">{audit.data.total} entries · inspect →</Link>} />
            <Stat icon={<Target size={13} />} label="Authorized scope" value={<span className="mono" style={{ fontSize: 18 }}>{m.host}</span>} foot={`${m.environment} · operator ${m.operator}`} />
            <Stat icon={<Gauge size={13} />} label="Rate cap" value={m.rate_cap} foot="enforced in the gated client" />
            <Stat icon={<Fingerprint size={13} />} label="Scope fingerprint" value={<span className="mono" style={{ fontSize: 16 }}>{shortHash(m.scope_fingerprint, 10)}</span>} foot={dateTime(m.started_at)} />
          </>
        ) : (
          <div className="card stat" style={{ gridColumn: "1 / -1" }}>
            <div className="text-2">Run an engagement to see its live authorization scope and audit verification here.</div>
          </div>
        )}
      </div>

      <h2 style={{ fontSize: 15, margin: "26px 0 12px" }}>Safety invariants</h2>
      <div className="grid g3">
        {INVARIANTS.map((iv, i) => (
          <Card key={iv.title}>
            <div className="callout" style={{ padding: 0 }}>
              <span className="ci">{iv.icon}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="row between">
                  <span className="muted mono" style={{ fontSize: 11 }}>INVARIANT {i + 1}</span>
                  <StatusPill tone="good">Enforced</StatusPill>
                </div>
                <div style={{ fontWeight: 600, margin: "4px 0" }}>{iv.title}</div>
                <div className="text-2" style={{ fontSize: 12.5 }}>{iv.body}</div>
                <div className="mono muted" style={{ fontSize: 11, marginTop: 8 }}>{iv.where}</div>
              </div>
            </div>
          </Card>
        ))}
        <Card>
          <div className="callout" style={{ padding: 0 }}>
            <span className="ci"><CheckCircle2 size={16} color="var(--good-text)" /></span>
            <div>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Verified in CI</div>
              <div className="text-2" style={{ fontSize: 12.5 }}>
                A dedicated <code>safety-invariants</code> job runs <code>tests/test_safety_invariants.py</code> on every push. Removing a control fails the build.
              </div>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}
