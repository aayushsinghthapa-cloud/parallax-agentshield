import { useCallback, useEffect, useRef, useState } from "react";
import type { Config, Mail, Run, RunRequest, Shield } from "./api";
import { approve, getJSON, newRun, reduce, streamRun } from "./api";
import type { AuditEntry } from "./components";
import {
  ApprovalModal, AttackerInbox, AuditTab, Badge, Chat, Counters, DecisionFeed, Logo, Pill, ShieldToggle, Trace,
} from "./components";
import { AttackStrip } from "./strip";
import { ResultsModal } from "./results";
import { CompareView } from "./compare";

type Tab = "decisions" | "audit" | "attacker";

export default function App() {
  const [config, setConfig] = useState<Config | null>(null);
  const [shield, setShield] = useState<Shield>("on");
  const [runs, setRuns] = useState<Run[]>([]);
  const [tab, setTab] = useState<Tab>("decisions");
  const [mail, setMail] = useState<Mail[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<{ ok: boolean; entries: number | null; broken_at: number | null } | null>(null);
  const [text, setText] = useState("");
  const [payload, setPayload] = useState("");
  const [backendDown, setBackendDown] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [compare, setCompare] = useState<string | null>(null);
  const autorun = useRef(false);

  const current = runs[runs.length - 1];
  const busy = current?.status === "running";

  const refreshAudit = useCallback(() => {
    getJSON<{ entries: AuditEntry[] }>("/api/audit?n=60").then((r) => setAudit(r.entries)).catch(() => {});
  }, []);

  const start = useCallback((req: RunRequest, message: string) => {
    const run = newRun(req, message);
    setRuns((rs) => [...rs, run]);
    streamRun(req, (ev, d) => {
      setRuns((rs) => rs.map((r) => (r.key === run.key ? reduce(r, ev, d) : r)));
      if (ev === "outbox" && d.attacker) setMail((m) => [...m, { ...d, shield: req.shield, scenario: run.scenario }]);
      if (ev === "done") refreshAudit();
    });
  }, [refreshAudit]);

  useEffect(() => {
    getJSON<Config>("/api/config").then(setConfig).catch(() => setBackendDown(true));
    getJSON<{ mail: Mail[] }>("/api/outbox").then((r) => setMail(r.mail.filter((m) => m.attacker))).catch(() => {});
    refreshAudit();
  }, [refreshAudit]);

  // ?run=S2&shield=off starts a scenario on load (used for screenshots and the demo).
  useEffect(() => {
    if (!config || autorun.current) return;
    const q = new URLSearchParams(location.search);
    if (q.get("results")) setShowResults(true);
    if (q.get("compare")) { autorun.current = true; setCompare(q.get("compare")); return; }
    const sid = q.get("run");
    const sh = (q.get("shield") as Shield) || "on";
    const sc = config.scenarios.find((s) => s.id === sid);
    if (!sc) return;
    autorun.current = true; // StrictMode runs effects twice; never start two runs
    setShield(sh);
    if (q.get("tab")) setTab(q.get("tab") as Tab);
    start({ scenario: sc.id, shield: sh }, sc.message);
  }, [config, start]);

  const answer = (choice: "approve" | "deny") => {
    if (current?.approval) approve(current.approval.decision.decision_id, choice).catch(() => {});
  };

  const attackerCount = mail.length;
  const permissive = (current?.plannerMode || config?.planner_mode) === "permissive";
  const llmMode = current?.llmMode || config?.llm_mode;

  return (
    <div className="h-full flex flex-col">
      {/* top bar */}
      <header className="border-b border-line bg-panel px-4 py-2 flex flex-col gap-1.5">
        <div className="flex items-center gap-4">
          <Logo />
          <div className="text-[13px] text-mute hidden xl:block max-w-[340px] leading-snug">
            Untrusted content cannot cause tool calls or data flows outside the user's task contract.
          </div>
          <div className="ml-auto flex items-center gap-3">
            <button
              onClick={() => setCompare(current && current.scenario.match(/^S\d$/) ? current.scenario : "S2")}
              disabled={busy || !config}
              className="rounded-md border border-red/60 text-red px-2.5 py-0.5 text-[13px] font-semibold hover:bg-red/10 disabled:opacity-40"
            >
              Compare OFF / ON
            </button>
            <button onClick={() => setShowResults(true)} className="rounded-md border border-line px-2.5 py-0.5 text-[13px] font-semibold hover:border-mute">Results</button>
            <Counters runs={runs} />
            <ShieldToggle shield={shield} onChange={setShield} disabled={busy} />
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap min-h-[26px]">
          <span className="text-[13px] text-mute mr-1">Task contract:</span>
          {current?.pills.length ? current.pills.map((p) => <Pill key={p} text={p} />) : <span className="text-[13px] text-mute">compiled from your request, before any tool runs</span>}
          <span className="ml-auto flex gap-2">
            {permissive && <Badge tone="amber">Permissive planner (simulates a vulnerable agent)</Badge>}
            {current?.scripted && <Badge tone="red" title="No tested model followed this injection, so this run's LLM is scripted. The guard still decides live.">Scripted attacker run</Badge>}
            {llmMode && <Badge tone={llmMode === "replay" ? "mute" : "green"}>{llmMode === "replay" ? "REPLAY" : "LIVE"}</Badge>}
          </span>
        </div>
      </header>

      {backendDown && (
        <div className="bg-amber/15 text-amber text-center py-1.5 text-[15px]">
          Can't reach the LEASH backend on :8000. Start it with ./run.sh.
        </div>
      )}

      <main className="flex-1 min-h-0 grid grid-cols-[28fr_44fr_28fr] gap-3 p-3">
        {/* left: chat + scenarios + live payload */}
        <section className="min-h-0 flex flex-col gap-3">
          <div className="flex-1 min-h-0 overflow-y-auto rounded-xl border border-line bg-panel p-3">
            <Chat runs={runs} />
          </div>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (text.trim() && !busy) { start({ message: text.trim(), shield }, text.trim()); setText(""); }
            }}
          >
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Ask the assistant…"
              className="flex-1 min-w-0 rounded-lg bg-panel2 border border-line px-3 py-2 text-[15px] outline-none focus:border-mute"
            />
            <button disabled={busy || !text.trim()} className="rounded-lg bg-ink text-bg font-bold px-3 disabled:opacity-40">Send</button>
          </form>
          <div className="grid grid-cols-2 gap-2">
            {config?.scenarios.map((s) => (
              <button
                key={s.id}
                disabled={busy}
                onClick={() => start({ scenario: s.id, shield }, s.message)}
                title={s.message}
                className="rounded-lg border border-line bg-panel2 hover:border-mute text-left px-2.5 py-1.5 text-[14px] disabled:opacity-40"
              >
                <span className="text-mute font-mono text-[12px] mr-1.5">{s.id}</span>{s.label}
              </button>
            ))}
          </div>
          <div className="rounded-xl border border-red/40 bg-red/5 p-2.5">
            <label htmlFor="payload" className="text-[13px] font-bold text-red">Live payload: arrives as a new email from unknown@external.example</label>
            <textarea
              id="payload"
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              rows={2}
              placeholder="Type any injection you like, judges welcome"
              className="mt-1 w-full rounded-md bg-bg border border-line px-2 py-1.5 text-[14px] font-mono outline-none focus:border-red/60 resize-none"
            />
            <button
              disabled={busy || !payload.trim()}
              onClick={() => start({ payload: payload.trim(), shield }, payload.trim())}
              className="mt-1 w-full rounded-md bg-red text-white font-bold py-1.5 text-[15px] disabled:opacity-40"
            >
              Inject &amp; run
            </button>
          </div>
        </section>

        {/* centre: path + live trace */}
        <section className="min-h-0 flex flex-col gap-3">
          <div className="rounded-xl border border-line bg-panel p-3">
            <div className="text-[12px] uppercase tracking-widest text-mute mb-2">Attack path</div>
            <AttackStrip run={current} />
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto rounded-xl border border-line bg-panel p-3">
            <div className="text-[12px] uppercase tracking-widest text-mute mb-2">
              Live trace {current && <span className="normal-case tracking-normal">· {current.scenario} · shield {current.shield.toUpperCase()}</span>}
            </div>
            <Trace run={current} />
          </div>
        </section>

        {/* right: tabs */}
        <section className="min-h-0 flex flex-col rounded-xl border border-line bg-panel">
          <div className="flex border-b border-line" role="tablist">
            {([["decisions", "Decisions"], ["audit", "Audit log"], ["attacker", "Attacker's inbox"]] as [Tab, string][]).map(([k, label]) => (
              <button
                key={k}
                role="tab"
                aria-selected={tab === k}
                onClick={() => { setTab(k); if (k === "audit") refreshAudit(); }}
                className={`flex-auto px-2 py-2 text-[13px] font-semibold whitespace-nowrap border-b-2 ${tab === k ? "border-ink text-ink" : "border-transparent text-mute"}`}
              >
                {label}
                {k === "attacker" && attackerCount > 0 && <span className="ml-1.5 rounded-full bg-red text-white text-[11px] px-1.5">{attackerCount}</span>}
              </button>
            ))}
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-3">
            {tab === "decisions" && <DecisionFeed runs={runs} />}
            {tab === "audit" && (
              <AuditTab
                entries={audit}
                verify={verify}
                onRefresh={refreshAudit}
                onVerify={() => getJSON<typeof verify>("/api/audit/verify").then(setVerify).catch(() => {})}
              />
            )}
            {tab === "attacker" && (
              <AttackerInbox mail={mail} onClear={() => getJSON("/api/reset", { method: "POST" }).then(() => setMail([])).catch(() => {})} />
            )}
          </div>
        </section>
      </main>

      {showResults && <ResultsModal onClose={() => setShowResults(false)} />}
      {compare && config && <CompareView config={config} initial={compare} onClose={() => setCompare(null)} />}
      {current?.approval && current.shield === "on" && (
        <ApprovalModal key={current.approval.decision.decision_id} pending={current.approval} timeoutS={config?.approval_timeout_s ?? 120} onAnswer={answer} />
      )}
    </div>
  );
}
