import { useEffect, useRef, useState } from "react";
import type { Call, Config, Decision, Mail, PendingApproval, Run, Shield, Verdict } from "./api";
import { describeCall, isAttack } from "./api";

// Agent and email text is always rendered as plain text (React escapes it). Never markdown or HTML:
// rendering an attacker's ![img](url) would itself be an exfiltration channel.

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <svg width="34" height="34" viewBox="0 0 32 32" aria-hidden>
        <rect width="32" height="32" rx="7" fill="#e23b2e" />
        <path d="M9 8v15h14" stroke="white" strokeWidth="3.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="23" cy="23" r="2.6" fill="white" />
      </svg>
      <div className="leading-none">
        <div className="text-[22px] font-extrabold tracking-[0.18em]">LEASH</div>
        <div className="text-[11px] text-mute mt-1 tracking-wide">a deterministic leash for AI agents</div>
      </div>
    </div>
  );
}

export function ShieldToggle({ shield, onChange, disabled }: { shield: Shield; onChange: (s: Shield) => void; disabled: boolean }) {
  const on = shield === "on";
  return (
    <button
      onClick={() => onChange(on ? "off" : "on")}
      disabled={disabled}
      aria-pressed={on}
      title={disabled ? "Wait for the current run to finish" : "Toggle the guard for the next run"}
      className={`flex items-center gap-3 rounded-full pl-2 pr-5 py-1.5 border-2 font-extrabold text-[17px] transition disabled:opacity-60 ${
        on ? "border-green bg-green/15 text-green" : "border-red bg-red/15 text-red"
      }`}
    >
      <span className={`relative w-12 h-7 rounded-full ${on ? "bg-green" : "bg-red"}`}>
        <span className={`absolute top-1 w-5 h-5 rounded-full bg-white transition-all ${on ? "left-6" : "left-1"}`} />
      </span>
      Shield {on ? "ON" : "OFF"}
    </button>
  );
}

export function Badge({ children, tone = "mute", title }: { children: React.ReactNode; tone?: "mute" | "amber" | "red" | "green"; title?: string }) {
  const c = {
    mute: "border-line text-mute",
    amber: "border-amber/60 text-amber bg-amber/10",
    red: "border-red/60 text-red bg-red/10",
    green: "border-green/60 text-green bg-green/10",
  }[tone];
  return (
    <span title={title} className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[13px] font-semibold whitespace-nowrap ${c}`}>
      {children}
    </span>
  );
}

export function Pill({ text }: { text: string }) {
  const locked = text === "Vault: locked";
  return (
    <span className={`rounded-full px-3 py-0.5 text-[14px] border whitespace-nowrap ${locked ? "border-amber/50 text-amber" : "border-line text-ink bg-panel2"}`}>
      {text}
    </span>
  );
}

export function VerdictChip({ verdict, shield }: { verdict: Verdict; shield: Shield }) {
  const label = { ALLOW: "ALLOWED", DENY: "BLOCKED", REQUIRE_APPROVAL: "ASKS YOU" }[verdict];
  const c = { ALLOW: "bg-green/15 text-green border-green/50", DENY: "bg-red/15 text-red border-red/60", REQUIRE_APPROVAL: "bg-amber/15 text-amber border-amber/60" }[verdict];
  if (shield === "off") {
    return verdict === "ALLOW" ? (
      <span className="rounded border border-line px-2 py-0.5 text-[12px] font-bold text-mute">RAN</span>
    ) : (
      <span className="rounded border border-dashed border-red/70 px-2 py-0.5 text-[12px] font-bold text-red/90" title="Shield is off: the guard ran in shadow mode">
        RAN · shield would have {verdict === "DENY" ? "blocked" : "asked"}
      </span>
    );
  }
  return <span className={`rounded border px-2 py-0.5 text-[12px] font-bold whitespace-nowrap ${c} ${verdict === "DENY" ? "slam" : ""}`}>{label}</span>;
}

// --- left column -----------------------------------------------------------------------

export function Chat({ runs }: { runs: Run[] }) {
  const end = useRef<HTMLDivElement>(null);
  const last = runs[runs.length - 1];
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [runs.length, last?.final, last?.error, last?.status]);
  if (!runs.length) {
    return <p className="text-mute text-[15px] p-1">Pick a scenario below, or type a request. Every action the assistant proposes goes through the LEASH gate.</p>;
  }
  return (
    <div className="space-y-3">
      {runs.map((r) => (
        <div key={r.key} className="space-y-1.5 rise">
          <div className="ml-6 rounded-xl rounded-br-sm bg-panel2 border border-line px-3 py-2 text-[15px]">
            <div className="text-[11px] text-mute mb-0.5">
              You · {r.scenario} · shield {r.shield.toUpperCase()}
            </div>
            {r.scenario === "LIVE" ? "Read my newest email and do what's needed." : r.message}
          </div>
          <div className="mr-6 rounded-xl rounded-bl-sm border border-line px-3 py-2 text-[15px]">
            <div className="text-[11px] text-mute mb-0.5">Assistant</div>
            {r.error ? (
              <span className="text-amber">{r.error}</span>
            ) : r.final !== undefined ? (
              <div className="whitespace-pre-wrap break-words max-h-48 overflow-y-auto">{r.final}</div>
            ) : (
              <span className="text-mute">{r.approval ? "Waiting for your OK…" : "Working…"}</span>
            )}
          </div>
        </div>
      ))}
      <div ref={end} />
    </div>
  );
}

// --- centre: compact path + live trace --------------------------------------------------

export function PathRow({ run }: { run?: Run }) {
  const tainted = !!run?.taint.length;
  const vault = !!run?.calls.some((c) => c.tool === "read_vault");
  const blocked = !!run?.calls.some((c) => c.decision && c.decision.verdict !== "ALLOW" && !c.executed && run.shield === "on");
  const sent = !!run?.outbox.some((m) => !m.attacker);
  const leaked = !!run?.outbox.some((m) => m.attacker);
  const node = (label: string, tone: string) => (
    <span className={`rounded-lg border px-1.5 py-1 text-[13px] font-semibold whitespace-nowrap ${tone}`}>{label}</span>
  );
  const arrow = <span className="text-mute">→</span>;
  return (
    <div className="flex flex-wrap items-center gap-1" aria-label="attack path">
      {node("You", "border-green/60 text-green")}
      {arrow}
      {node("Inbox / Docs", tainted ? "border-red text-red bg-red/10" : "border-line text-mute")}
      {node("Vault", vault ? "border-amber text-amber bg-amber/10" : "border-line text-mute")}
      {arrow}
      {node(blocked ? "LEASH gate · shut" : "LEASH gate", blocked ? "border-red bg-red text-white slam" : "border-line text-ink")}
      {arrow}
      {node("Outbox", sent ? "border-green/60 text-green" : "border-line text-mute")}
      {node("Attacker's inbox", leaked ? "border-red bg-red/20 text-red" : "border-line text-mute")}
    </div>
  );
}

export function Trace({ run }: { run?: Run }) {
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [run?.calls.length, run?.status]);
  if (!run) return <p className="text-mute">The live trace of the next run appears here.</p>;
  return (
    <ol className="space-y-2">
      {run.calls.map((c, i) => {
        return (
          <li key={c.id + i} className="rise">
            <div className={`rounded-lg border px-3 py-2 ${c.decision?.verdict === "DENY" && run.shield === "on" ? "border-red/50 bg-red/5" : "border-line bg-panel2"}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="text-[15px] font-semibold [overflow-wrap:anywhere]">{describeCall(c)}</div>
                {c.decision ? <VerdictChip verdict={c.decision.verdict} shield={run.shield} /> : <span className="text-mute text-[12px]">checking…</span>}
              </div>
              {c.decision && (
                <div className="text-[14px] text-mute mt-1">
                  {c.decision.reason_plain}
                  {c.approval && <span className="text-amber"> · You said {c.approval === "approve" ? "yes, once" : "no"}.</span>}
                  {run.shield === "on" && c.executed === false && <span className="text-ink"> Nothing was sent.</span>}
                </div>
              )}
            </div>
            {c.taintedBy && (
              <div className="text-[13px] text-red mt-1 ml-3">⚠ Untrusted content entered: {c.taintedBy}. Session is now tainted.</div>
            )}
          </li>
        );
      })}
      {run.thinking && <li className="text-mute text-[14px] animate-pulse">Assistant is thinking…</li>}
      {run.status === "done" && !run.calls.length && <li className="text-mute">No actions were proposed.</li>}
      <div ref={end} />
    </ol>
  );
}

// --- right column -----------------------------------------------------------------------

export function DecisionFeed({ runs }: { runs: Run[] }) {
  const items = runs.flatMap((r) => r.calls.filter((c) => c.decision).map((c) => ({ r, c }))).reverse().slice(0, 40);
  if (!items.length) return <p className="text-mute">Each guard decision shows up here, with the reason in plain words.</p>;
  return (
    <div className="space-y-2">
      {items.map(({ r, c }) => (
        <DecisionCard key={r.key + c.id} run={r} call={c} />
      ))}
    </div>
  );
}

function DecisionCard({ run, call }: { run: Run; call: Call }) {
  const [open, setOpen] = useState(false);
  const d = call.decision as Decision;
  const blocked = run.shield === "on" && call.executed === false && d.verdict !== "ALLOW";
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3 py-2 rise">
      <div className="flex items-center justify-between gap-2">
        <VerdictChip verdict={d.verdict} shield={run.shield} />
        <span className="text-[11px] text-mute">{run.scenario}</span>
      </div>
      <div className="text-[14px] font-semibold mt-1.5 [overflow-wrap:anywhere]">{describeCall(call)}</div>
      <div className="text-[14px] mt-0.5">{d.reason_plain}</div>
      {blocked && <div className="text-[14px] font-semibold mt-0.5">Nothing was sent.</div>}
      <button onClick={() => setOpen(!open)} className="text-[12px] text-mute underline mt-1">
        {open ? "hide details" : "details"}
      </button>
      {open && (
        <dl className="mt-1 text-[12px] font-mono text-mute space-y-0.5 [overflow-wrap:anywhere]">
          <div><dt className="inline text-ink">rule </dt><dd className="inline">{d.rule_id}</dd></div>
          {Object.entries(d.arg_provenance).map(([k, v]) => (
            <div key={k}><dt className="inline text-ink">{k} </dt><dd className={`inline ${v === "tainted" ? "text-red" : v === "user-literal" ? "text-green" : ""}`}>{v}</dd></div>
          ))}
          {d.source_ref && <div><dt className="inline text-ink">source </dt><dd className="inline">{d.source_ref}</dd></div>}
          <div><dt className="inline text-ink">why </dt><dd className="inline">{d.reason_tech}</dd></div>
          <div><dt className="inline text-ink">latency </dt><dd className="inline">{d.latency_ms} ms · policy {d.policy_version}</dd></div>
        </dl>
      )}
    </div>
  );
}

export interface AuditEntry {
  ts: number;
  event?: string;
  tool?: string;
  verdict?: string;
  would_have?: string | null;
  rule_id?: string;
  choice?: string;
  shield_mode?: string;
  hash: string;
}

export function AuditTab({ entries, verify, onVerify, onRefresh }: {
  entries: AuditEntry[];
  verify: { ok: boolean; entries: number | null; broken_at: number | null } | null;
  onVerify: () => void;
  onRefresh: () => void;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <button onClick={onVerify} className="rounded-md bg-ink text-bg font-bold text-[14px] px-3 py-1">Verify chain</button>
        <button onClick={onRefresh} className="rounded-md border border-line text-[14px] px-3 py-1">Refresh</button>
        {verify && (
          <span className={`text-[14px] font-semibold ${verify.ok ? "text-green" : "text-red"}`}>
            {verify.ok ? `✓ chain intact (${verify.entries} entries)` : `✗ chain broken at entry ${verify.broken_at}`}
          </span>
        )}
      </div>
      <p className="text-[12px] text-mute mb-2">Append-only, SHA-256 hash-chained. Secrets are masked before writing.</p>
      <div className="space-y-1 font-mono text-[12px]">
        {[...entries].reverse().map((e) => (
          <div key={e.hash} className="flex gap-2 border-b border-line/60 pb-1">
            <span className="text-mute">{new Date(e.ts * 1000).toLocaleTimeString()}</span>
            {e.event === "approval" ? (
              <span className="text-amber">approval → {e.choice}</span>
            ) : (
              <>
                <span className="text-ink">{e.tool}</span>
                <span className={e.verdict === "DENY" || e.would_have === "DENY" ? "text-red" : e.verdict === "REQUIRE_APPROVAL" || e.would_have === "REQUIRE_APPROVAL" ? "text-amber" : "text-green"}>
                  {e.shield_mode === "off" ? `ran (would ${e.would_have})` : e.verdict}
                </span>
                <span className="text-mute truncate">{e.rule_id}</span>
              </>
            )}
            <span className="ml-auto text-mute">{e.hash.slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AttackerInbox({ mail, onClear }: { mail: Mail[]; onClear: () => void }) {
  if (!mail.length) {
    return (
      <div className="text-center py-8">
        <div className="text-[32px]">∅</div>
        <p className="text-mute">Nothing has reached the attacker.</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <span className="text-[13px] text-red font-semibold">{mail.length} email{mail.length === 1 ? "" : "s"} leaked</span>
        <button onClick={onClear} className="text-[12px] text-mute underline">Clear</button>
      </div>
      {[...mail].reverse().map((m, i) => (
        <div key={m.run_id + i} className="rounded-lg border border-red/60 bg-red/10 px-3 py-2 rise">
          <div className="text-[12px] text-red font-bold">LEAKED · {m.scenario} · shield {m.shield?.toUpperCase()}</div>
          <div className="text-[14px]"><span className="text-mute">To:</span> {m.to}</div>
          <div className="text-[14px]"><span className="text-mute">Subject:</span> {m.subject}</div>
          <pre className="font-mono text-[12px] whitespace-pre-wrap [overflow-wrap:anywhere] mt-1 text-ink/90">{m.body}</pre>
        </div>
      ))}
    </div>
  );
}

// --- approval modal -----------------------------------------------------------------------

const VERBS: Record<string, { want: string; yes: string; no: string; target: string }> = {
  send_email: { want: "send an email", yes: "Send once", no: "Don't send", target: "To" },
  delete_files: { want: "delete files", yes: "Delete once", no: "Don't delete", target: "Files" },
  fetch_url: { want: "open a web address", yes: "Open once", no: "Don't open", target: "Address" },
};

export function ApprovalModal({ pending, timeoutS, onAnswer }: {
  pending: PendingApproval;
  timeoutS: number;
  onAnswer: (choice: "approve" | "deny") => void;
}) {
  const [details, setDetails] = useState(false);
  const [left, setLeft] = useState(timeoutS);
  const noBtn = useRef<HTMLButtonElement>(null);
  useEffect(() => noBtn.current?.focus(), []);
  useEffect(() => {
    const t = setInterval(() => setLeft(Math.max(0, timeoutS - Math.floor((Date.now() - pending.since) / 1000))), 500);
    return () => clearInterval(t);
  }, [pending.since, timeoutS]);

  const v = VERBS[pending.tool] ?? { want: "do something", yes: "Allow once", no: "Don't allow", target: "Target" };
  const a = pending.args;
  const target = String(a.to ?? a.path ?? a.url ?? "");
  const ex = pending.decision.extra as { secret_labels?: string[]; docs?: string[] };
  const contains = ex.secret_labels?.length
    ? `your ${ex.secret_labels.join(" and ")} (marked secret)`
    : ex.docs?.length
      ? `content from ${ex.docs.join(", ")} (marked confidential)`
      : null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="appr-title">
      <div className="w-[560px] max-w-full rounded-2xl border-2 border-amber bg-panel p-6 shadow-2xl rise">
        <h2 id="appr-title" className="text-[22px] font-extrabold leading-tight">
          Your assistant wants to {v.want}. Check this first.
        </h2>
        <dl className="mt-4 space-y-2 text-[17px]">
          {target && <div><dt className="inline font-bold">{v.target}: </dt><dd className="inline [overflow-wrap:anywhere]">{target}</dd></div>}
          {contains && <div><dt className="inline font-bold">Contains: </dt><dd className="inline">{contains}</dd></div>}
          <div><dt className="inline font-bold">Why we're asking: </dt><dd className="inline">{pending.decision.reason_plain}</dd></div>
          <div><dt className="inline font-bold">You asked: </dt><dd className="inline">“{pending.userRequest}”</dd></div>
        </dl>
        {details && (
          <div className="mt-3 rounded-lg bg-panel2 border border-line p-3 text-[13px] font-mono text-mute [overflow-wrap:anywhere]">
            rule {pending.decision.rule_id} · {pending.decision.reason_tech}
          </div>
        )}
        <div className="mt-5 flex items-center gap-3">
          <button ref={noBtn} onClick={() => onAnswer("deny")} className="rounded-lg bg-ink text-bg font-extrabold text-[17px] px-5 py-2.5 outline-offset-4 focus:outline-3 focus:outline-amber">
            {v.no}
          </button>
          <button onClick={() => onAnswer("approve")} className="rounded-lg border-2 border-line font-bold text-[17px] px-5 py-2">
            {v.yes}
          </button>
          <button onClick={() => setDetails(!details)} className="text-[15px] text-mute underline ml-auto">
            {details ? "Hide details" : "See details"}
          </button>
        </div>
        <p className="mt-3 text-[13px] text-mute">If you don't answer in {left}s, nothing is sent.</p>
      </div>
    </div>
  );
}

export function Counters({ runs }: { runs: Run[] }) {
  const done = runs.filter((r) => r.status === "done" && !r.error);
  const legit = done.filter((r) => !r.calls.some((c) => isAttack(c, r)));
  const prompts = legit.reduce((n, r) => n + r.calls.filter((c) => c.decision?.verdict === "REQUIRE_APPROVAL" && r.shield === "on").length, 0);
  const attacks = runs.flatMap((r) => r.calls.filter((c) => isAttack(c, r)));
  const stopped = attacks.filter((c) => c.executed === false).length;
  return (
    <div className="flex gap-2 text-[14px]">
      <Badge tone="green">Legit tasks: {legit.length} · prompts: {prompts}</Badge>
      <Badge tone={stopped < attacks.length ? "red" : "mute"}>Attacks: {attacks.length} · stopped: {stopped}</Badge>
    </div>
  );
}

export type { Config };
