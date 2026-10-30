import { useCallback, useEffect, useRef, useState } from "react";
import type { Config, Run, RunRequest, Shield } from "./api";
import { approve, newRun, reduce, streamRun } from "./api";
import { ApprovalModal, Badge, Trace } from "./components";
import { AttackStrip } from "./strip";

// Split-screen: the same scenario with the shield OFF, then ON, side by side.
// Runs are sequential so the replayed (or live) model answers are the same input both times.

export function CompareView({ config, initial, onClose }: { config: Config; initial?: string; onClose: () => void }) {
  const [sid, setSid] = useState(initial ?? "S2");
  const [runs, setRuns] = useState<Partial<Record<Shield, Run>>>({});
  const busy = Object.values(runs).some((r) => r?.status === "running");
  const started = useRef(false);

  const runOne = useCallback((shield: Shield, scenario: string, then?: () => void) => {
    const sc = config.scenarios.find((s) => s.id === scenario)!;
    const req: RunRequest = { scenario, shield };
    setRuns((rs) => ({ ...rs, [shield]: newRun(req, sc.message) }));
    streamRun(req, (ev, d) => {
      setRuns((rs) => (rs[shield] ? { ...rs, [shield]: reduce(rs[shield]!, ev, d) } : rs));
      if (ev === "done") then?.();
    });
  }, [config]);

  const go = useCallback((scenario: string) => {
    setSid(scenario);
    setRuns({});
    runOne("off", scenario, () => runOne("on", scenario));
  }, [runOne]);

  useEffect(() => {
    if (started.current) return;
    started.current = true; // StrictMode: start once
    go(sid);
  }, [go, sid]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && !busy && onClose();
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [busy, onClose]);

  const pending = runs.on?.approval;
  return (
    <div className="fixed inset-0 z-40 bg-bg flex flex-col" role="dialog" aria-modal="true" aria-label="Compare shield off and on">
      <div className="flex items-center gap-3 border-b border-line bg-panel px-4 py-2">
        <span className="text-[20px] font-extrabold tracking-wide">Same attack, two outcomes</span>
        <div className="flex gap-1.5 ml-4">
          {config.scenarios.map((s) => (
            <button
              key={s.id}
              disabled={busy}
              onClick={() => go(s.id)}
              title={s.message}
              className={`rounded-md border px-2.5 py-1 text-[14px] disabled:opacity-40 ${s.id === sid ? "border-ink bg-ink text-bg font-bold" : "border-line"}`}
            >
              {s.id} {s.label}
            </button>
          ))}
        </div>
        <button onClick={onClose} disabled={busy} className="ml-auto rounded-md border border-line px-3 py-1 text-[14px] disabled:opacity-40">Close</button>
      </div>
      <div className="px-4 pt-2 flex items-center gap-2 text-[15px] text-mute">
        <span>You: “{config.scenarios.find((s) => s.id === sid)?.message}”</span>
        <span className="ml-auto flex gap-2">
          {(runs.off?.plannerMode || config.planner_mode) === "permissive" && <Badge tone="amber">Permissive planner (simulates a vulnerable agent)</Badge>}
          {(runs.off?.scripted || runs.on?.scripted) && <Badge tone="red">Scripted attacker run</Badge>}
          <Badge>{(runs.off?.llmMode || config.llm_mode) === "replay" ? "REPLAY" : "LIVE"}</Badge>
        </span>
      </div>
      <div className="flex-1 min-h-0 grid grid-cols-2 gap-3 p-3">
        {(["off", "on"] as Shield[]).map((sh) => (
          <Side key={sh} shield={sh} run={runs[sh]} />
        ))}
      </div>
      {pending && (
        <ApprovalModal key={pending.decision.decision_id} pending={pending} timeoutS={config.approval_timeout_s}
          onAnswer={(c) => approve(pending.decision.decision_id, c).catch(() => {})} />
      )}
    </div>
  );
}

function Side({ shield, run }: { shield: Shield; run?: Run }) {
  const on = shield === "on";
  const leaked = run?.outbox.filter((m) => m.attacker).length ?? 0;
  return (
    <section className={`min-h-0 flex flex-col rounded-xl border-2 ${on ? "border-green/60" : "border-red/60"} bg-panel`}>
      <div className={`flex items-center justify-between px-3 py-2 border-b border-line ${on ? "text-green" : "text-red"}`}>
        <span className="text-[18px] font-extrabold">Shield {on ? "ON" : "OFF"}</span>
        <span className="text-[14px] font-semibold">
          {!run ? "waiting…" : run.status === "running" ? "running…" : leaked ? `${leaked} leak${leaked > 1 ? "s" : ""} to the attacker` : "nothing leaked"}
        </span>
      </div>
      <div className="px-3 pt-2">
        <AttackStrip run={run} />
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto px-3 pb-3">
        {run ? <Trace run={run} /> : <p className="text-mute">Starts when the shield-OFF run finishes.</p>}
      </div>
    </section>
  );
}
