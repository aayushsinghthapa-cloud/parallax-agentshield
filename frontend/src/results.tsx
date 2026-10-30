import { useEffect, useState } from "react";
import { getJSON } from "./api";

// Evidence from backend/scripts/eval.py. Rendered from JSON as plain tables (no markdown rendering).

interface Results {
  policy_version: string;
  generated: number;
  bypass: { variant: string; tool: string; rule_id: string; verdict: string; pass: boolean }[];
  friction: { task: string; calls: number; prompts: number; blocks: number }[];
  scenarios: {
    scenario: string; label: string; scripted: boolean;
    off: { pass: boolean; leaked_to_attacker: number; executed_risky: number };
    on: { pass: boolean; leaked_to_attacker: number; non_allow: number; prompts: number; rules: string[] };
  }[];
  latency: { n: number; p50_ms: number; p95_ms: number; max_ms: number };
}

const th = "text-left font-semibold text-mute px-2 py-1 border-b border-line";
const td = "px-2 py-1 border-b border-line/50 align-top";

export function ResultsModal({ onClose }: { onClose: () => void }) {
  const [r, setR] = useState<Results | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    getJSON<Results>("/api/results").then(setR).catch(() => setErr("No results yet. Run backend/scripts/eval.py."));
  }, []);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 bg-black/75 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Results" onClick={onClose}>
      <div className="w-[1100px] max-w-full max-h-full overflow-y-auto rounded-2xl border border-line bg-panel p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-[22px] font-extrabold">Results</h2>
          <button onClick={onClose} className="rounded-md border border-line px-3 py-1 text-[14px]">Close</button>
        </div>
        {err && <p className="text-amber mt-3">{err}</p>}
        {r && (
          <>
            <div className="grid grid-cols-4 gap-3 mt-3">
              <Stat big={`${r.bypass.filter((b) => b.pass).length}/${r.bypass.length}`} label="attack variants stopped" tone="text-green" />
              <Stat big={`${r.friction.filter((f) => !f.prompts && !f.blocks).length}/${r.friction.length}`} label="everyday tasks with 0 friction" tone="text-green" />
              <Stat big={`${r.scenarios.filter((s) => s.on.pass && s.off.pass).length}/${r.scenarios.length}`} label="scenarios as expected (off & on)" tone="text-ink" />
              <Stat big={`${r.latency.p95_ms} ms`} label={`guard p95 over ${r.latency.n} decisions`} tone="text-ink" />
            </div>
            <h3 className="font-bold mt-5 mb-1">Before / after</h3>
            <table className="w-full text-[14px]">
              <thead><tr><th className={th}>Scenario</th><th className={th}>Shield OFF</th><th className={th}>Shield ON</th><th className={th}>Rules (ON)</th></tr></thead>
              <tbody>
                {r.scenarios.map((s) => (
                  <tr key={s.scenario}>
                    <td className={td}>{s.scenario} {s.label}{s.scripted && <span className="text-red text-[12px]"> (scripted LLM)</span>}</td>
                    <td className={`${td} ${s.off.leaked_to_attacker ? "text-red font-semibold" : ""}`}>
                      {s.off.leaked_to_attacker ? `${s.off.leaked_to_attacker} leak to attacker` : s.off.executed_risky ? `${s.off.executed_risky} risky action ran` : "completed"}
                    </td>
                    <td className={`${td} text-green`}>
                      {s.on.leaked_to_attacker ? `${s.on.leaked_to_attacker} leak` : s.on.non_allow ? `${s.on.non_allow - s.on.prompts} blocked${s.on.prompts ? `, ${s.on.prompts} asked` : ""}` : "completed, 0 prompts"}
                    </td>
                    <td className={`${td} font-mono text-[12px] text-mute`}>{s.on.rules.join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="grid grid-cols-2 gap-5 mt-5">
              <div>
                <h3 className="font-bold mb-1">Bypass suite</h3>
                <table className="w-full text-[13px]">
                  <thead><tr><th className={th}>Variant</th><th className={th}>Caught by</th><th className={th}>Verdict</th></tr></thead>
                  <tbody>
                    {r.bypass.map((b) => (
                      <tr key={b.variant}>
                        <td className={td}>{b.variant.slice(3).replace(/_/g, " ")}</td>
                        <td className={`${td} font-mono text-[12px]`}>{b.rule_id}</td>
                        <td className={`${td} ${b.verdict === "DENY" ? "text-red" : "text-amber"}`}>{b.verdict === "DENY" ? "blocked" : "asks you"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div>
                <h3 className="font-bold mb-1">Friction suite</h3>
                <table className="w-full text-[13px]">
                  <thead><tr><th className={th}>Everyday task</th><th className={th}>Prompts</th><th className={th}>Blocks</th></tr></thead>
                  <tbody>
                    {r.friction.map((f) => (
                      <tr key={f.task}><td className={td}>{f.task}</td><td className={td}>{f.prompts}</td><td className={td}>{f.blocks}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <p className="text-[12px] text-mute mt-4">
              Policy {r.policy_version} · generated {new Date(r.generated * 1000).toLocaleString()} by backend/scripts/eval.py. Full write-up: docs/RESULTS.md.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

function Stat({ big, label, tone }: { big: string; label: string; tone: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel2 p-3">
      <div className={`text-[28px] font-extrabold ${tone}`}>{big}</div>
      <div className="text-[13px] text-mute">{label}</div>
    </div>
  );
}
