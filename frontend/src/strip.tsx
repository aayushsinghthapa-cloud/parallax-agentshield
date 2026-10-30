import type { Run } from "./api";
import { isAttack } from "./api";

// The attack path, drawn from the run's events. Edges light up in the order data would flow:
// You -> Inbox/Docs -> (Vault) -> LEASH gate -> Outbox | Attacker's inbox.

const W = 560;
const H = 160;
const NW = 92; // node width
const NH = 36;
const P = {
  you: { x: 58, y: 80 },
  inbox: { x: 192, y: 42 },
  vault: { x: 192, y: 122 },
  gate: { x: 322, y: 80 },
  out: { x: 488, y: 42 },
  atk: { x: 488, y: 122 },
};
const GATE_HALF = 16; // the gate is narrow; edges stop at its sides

const curve = (x1: number, y1: number, x2: number, y2: number) => {
  const m = (x1 + x2) / 2;
  return `M${x1} ${y1} C${m} ${y1} ${m} ${y2} ${x2} ${y2}`;
};
const right = (n: { x: number; y: number }) => [n.x + NW / 2, n.y] as const;
const left = (n: { x: number; y: number }) => [n.x - NW / 2, n.y] as const;

const COLORS = { idle: "#2a2a36", green: "#2fbf71", red: "#e23b2e", amber: "#f0a020", ink: "#9a9aab" };
type Tone = keyof typeof COLORS;

function Edge({ d, tone }: { d: string; tone: Tone }) {
  const on = tone !== "idle";
  return (
    <g>
      <path d={d} fill="none" stroke={COLORS.idle} strokeWidth={3} />
      {on && (
        <>
          {/* key: re-mount when the tone changes so the draw-in animation replays */}
          <path key={tone} d={d} fill="none" stroke={COLORS[tone]} strokeWidth={4} strokeLinecap="round" className="edge-draw" pathLength={100} />
          <path d={d} fill="none" stroke="white" strokeOpacity={0.55} strokeWidth={2} className="edge-flow" />
        </>
      )}
    </g>
  );
}

function Node({ at, label, tone, sub }: { at: { x: number; y: number }; label: string; tone: Tone; sub?: string }) {
  const c = COLORS[tone];
  const lit = tone !== "idle";
  return (
    <g transform={`translate(${at.x - NW / 2} ${at.y - NH / 2})`} className={lit ? "node-lit" : ""}>
      <rect width={NW} height={NH} rx={9} fill={lit ? c : "#13131a"} fillOpacity={lit ? 0.16 : 1} stroke={lit ? c : "#3a3a48"} strokeWidth={2} />
      <text x={NW / 2} y={sub ? 15 : NH / 2 + 5} textAnchor="middle" fontSize={13} fontWeight={700} fill={lit ? c : "#9a9aab"}>
        {label}
      </text>
      {sub && (
        <text x={NW / 2} y={29} textAnchor="middle" fontSize={10.5} fill={lit ? c : "#9a9aab"}>
          {sub}
        </text>
      )}
    </g>
  );
}

function Gate({ state }: { state: "idle" | "open" | "shut" | "shadow" }) {
  const shut = state === "shut";
  const col = shut ? COLORS.red : state === "open" ? COLORS.green : state === "shadow" ? "#5a5a6a" : COLORS.ink;
  const { x, y } = P.gate;
  return (
    <g>
      {/* posts */}
      <rect x={x - GATE_HALF - 3} y={y - 50} width={6} height={100} rx={2} fill={col} />
      <rect x={x + GATE_HALF - 3} y={y - 50} width={6} height={100} rx={2} fill={col} />
      {/* doors swing shut toward the centre */}
      <g key={state} className={shut ? "gate-slam" : ""} style={{ transformOrigin: `${x}px ${y}px` }}>
        <rect x={x - GATE_HALF + 2} y={y - 42} width={GATE_HALF - 2} height={84} rx={2}
          fill={col} fillOpacity={shut ? 0.9 : 0.15}
          className="door door-l" style={{ transform: shut ? "none" : "scaleX(0.25)", transformOrigin: `${x - GATE_HALF}px ${y}px` }} />
        <rect x={x} y={y - 42} width={GATE_HALF - 2} height={84} rx={2}
          fill={col} fillOpacity={shut ? 0.9 : 0.15}
          className="door door-r" style={{ transform: shut ? "none" : "scaleX(0.25)", transformOrigin: `${x + GATE_HALF}px ${y}px` }} />
      </g>
      {shut && (
        <text x={x} y={y + 6} textAnchor="middle" fontSize={20} fontWeight={800} fill="white" className="gate-slam">✕</text>
      )}
      <text x={x} y={y - 58} textAnchor="middle" fontSize={12} fontWeight={800} letterSpacing="0.14em" fill={col}>
        {state === "shadow" ? "LEASH (shadow)" : "LEASH"}
      </text>
    </g>
  );
}

export function AttackStrip({ run }: { run?: Run }) {
  const calls = run?.calls ?? [];
  const on = run?.shield !== "off";
  const tainted = !!run?.taint.length;
  const attack = !!run && calls.some((c) => isAttack(c, run));
  const vaultCalls = calls.filter((c) => c.tool === "read_vault");
  const vaultRead = vaultCalls.some((c) => c.executed);
  const sinkProposed = calls.some((c) => ["send_email", "fetch_url"].includes(c.tool));
  const blocked = !!run && on && calls.filter((c) => c.decision && c.decision.verdict !== "ALLOW" && c.executed === false);
  const leakedByUrl = calls.some((c) => c.tool === "fetch_url" && c.executed && c.afterTaint);
  const leaked = !!run && (run.outbox.some((m) => m.attacker) || leakedByUrl);
  const sentOk = !!run?.outbox.some((m) => !m.attacker);
  const shadowWouldBlock = !on ? calls.filter((c) => c.decision && c.decision.verdict !== "ALLOW").length : 0;
  const lastBlock = blocked ? blocked[blocked.length - 1] : undefined;

  const gate: "idle" | "open" | "shut" | "shadow" = !run ? "idle" : !on ? "shadow" : lastBlock ? "shut" : sinkProposed || calls.length ? "open" : "idle";

  const tones = {
    youInbox: (calls.length ? "green" : "idle") as Tone,
    inboxGate: (attack ? "red" : sinkProposed ? "ink" : "idle") as Tone,
    vaultGate: (vaultRead && sinkProposed ? "amber" : "idle") as Tone,
    gateOut: (sentOk ? "green" : "idle") as Tone,
    gateAtk: (leaked ? "red" : "idle") as Tone,
  };

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Attack path from your request to the outbox or the attacker's inbox">
        <Edge d={curve(...right(P.you), ...left(P.inbox))} tone={tones.youInbox} />
        <Edge d={curve(...right(P.inbox), P.gate.x - GATE_HALF, P.gate.y)} tone={tones.inboxGate} />
        <Edge d={curve(...right(P.vault), P.gate.x - GATE_HALF, P.gate.y)} tone={tones.vaultGate} />
        <Edge d={curve(P.gate.x + GATE_HALF, P.gate.y, ...left(P.out))} tone={tones.gateOut} />
        <Edge d={curve(P.gate.x + GATE_HALF, P.gate.y, ...left(P.atk))} tone={tones.gateAtk} />

        <Node at={P.you} label="You" tone={run ? "green" : "idle"} />
        <Node at={P.inbox} label="Inbox / Docs" tone={tainted ? "red" : "idle"} sub={tainted ? "tainted" : undefined} />
        <Node at={P.vault} label="Vault" tone={vaultCalls.length ? "amber" : "idle"} sub={vaultRead ? "opened" : vaultCalls.length ? "asked for" : undefined} />
        <Gate state={gate} />
        <Node at={P.out} label="Outbox" tone={sentOk ? "green" : "idle"} />
        <Node at={P.atk} label="Attacker" tone={leaked ? "red" : "idle"} sub={leaked ? "received data" : "inbox"} />
      </svg>
      <div className="min-h-[24px] text-[14px] mt-1" aria-live="polite">
        {run?.error && !lastBlock ? (
          <span className="text-amber">{run.error}</span>
        ) : lastBlock ? (
          <span key={lastBlock.id} className="text-red font-semibold slam inline-block">
            Gate shut: {lastBlock.decision?.reason_plain} Nothing was sent.
          </span>
        ) : !on && shadowWouldBlock ? (
          <span className="text-red/90">Shield OFF: LEASH only watched. It would have stopped {shadowWouldBlock} action{shadowWouldBlock > 1 ? "s" : ""}.</span>
        ) : run && run.status === "done" && !leaked ? (
          <span className="text-green">Nothing left the workspace that you didn't ask for.</span>
        ) : (
          <span className="text-mute">{run ? "Watching every action…" : "Run a scenario to see the path."}</span>
        )}
      </div>
    </div>
  );
}
