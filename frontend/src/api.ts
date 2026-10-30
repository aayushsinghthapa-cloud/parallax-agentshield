// Types mirror backend/guard/policy.py Decision and the SSE events from backend/agent/loop.py.

export type Verdict = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
export type Shield = "on" | "off";

export interface Decision {
  verdict: Verdict;
  rule_id: string;
  reason_plain: string;
  reason_tech: string;
  tool: string;
  arg_provenance: Record<string, string>;
  source_ref: string | null;
  latency_ms: number;
  policy_version: string;
  decision_id: string;
  extra: Record<string, unknown>;
}

export interface Call {
  id: string;
  tool: string;
  args: Record<string, unknown> | string;
  decision?: Decision;
  result?: string;
  executed?: boolean;
  approval?: "approve" | "deny";
  afterTaint: boolean; // was the session already tainted when this was proposed?
  taintedBy?: string; // this call's result tainted the session (source ref)
}

export interface Mail {
  run_id: string;
  to: string;
  subject: string;
  body: string;
  internal: boolean;
  attacker: boolean;
  shield?: Shield;
  scenario?: string;
}

export interface PendingApproval {
  decision: Decision;
  tool: string;
  args: Record<string, unknown>;
  userRequest: string;
  since: number;
}

export interface Run {
  key: string; // client-side, never changes (state updaters must stay pure)
  id: string; // server run id, known after "start"
  scenario: string;
  message: string;
  shield: Shield;
  plannerMode: string;
  llmMode: string;
  scripted: boolean;
  pills: string[];
  calls: Call[];
  taint: { source: string; kind: string }[];
  outbox: Mail[];
  thinking: boolean;
  final?: string;
  error?: string;
  approval?: PendingApproval;
  status: "running" | "done";
}

export interface Config {
  planner_mode: string;
  llm_mode: string;
  providers: string[];
  scenarios: { id: string; label: string; message: string }[];
  approval_timeout_s: number;
}

export interface RunRequest {
  scenario?: string;
  message?: string;
  payload?: string;
  shield: Shield;
}

export const getJSON = async <T,>(url: string, init?: RequestInit): Promise<T> => {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.json() as Promise<T>;
};

export const approve = (decision_id: string, choice: "approve" | "deny") =>
  getJSON("/api/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision_id, choice }),
  });

/** Apply one SSE event to a run. Pure, so React state updates stay predictable. */
export function reduce(run: Run, ev: string, d: any): Run {
  const patchCall = (id: string, f: (c: Call) => Call) => ({
    ...run,
    calls: run.calls.map((c) => (c.id === id ? f(c) : c)),
  });
  switch (ev) {
    case "start":
      return { ...run, id: d.run_id, plannerMode: d.planner_mode, llmMode: d.llm_mode, scripted: !!d.scripted };
    case "contract":
      return { ...run, pills: d.pills };
    case "llm_thinking":
      return { ...run, thinking: true };
    case "tool_proposed":
      return {
        ...run,
        thinking: false,
        calls: [...run.calls, { id: d.call_id, tool: d.tool, args: d.args, afterTaint: run.taint.length > 0 }],
      };
    case "decision":
      return patchCall(d.call_id, (c) => ({ ...c, decision: d.decision }));
    case "approval_required":
      return {
        ...run,
        approval: { decision: d.decision, tool: d.tool, args: d.args, userRequest: d.user_request, since: Date.now() },
      };
    case "approval_resolved":
      return { ...patchCall(d.call_id, (c) => ({ ...c, approval: d.choice })), approval: undefined };
    case "tool_result":
      return patchCall(d.call_id, (c) => ({ ...c, result: d.result, executed: d.executed }));
    case "taint_set": {
      // Sent right after the call that produced it, so it belongs to the latest call.
      const last = run.calls[run.calls.length - 1];
      const withTaint = last ? patchCall(last.id, (c) => ({ ...c, taintedBy: d.source })) : run;
      return { ...withTaint, taint: [...run.taint, { source: d.source, kind: d.kind }] };
    }
    case "outbox":
      return { ...run, outbox: [...run.outbox, d] };
    case "final":
      return { ...run, thinking: false, final: d.text };
    case "error":
      return { ...run, thinking: false, error: d.message };
    case "done":
      return { ...run, thinking: false, status: "done", approval: undefined };
    default:
      return run;
  }
}

const EVENTS = [
  "start", "contract", "llm_thinking", "tool_proposed", "decision", "tool_result", "taint_set",
  "approval_required", "approval_resolved", "outbox", "final", "error", "done",
];

/** Open the SSE stream for one run. Returns a function that closes it. */
export function streamRun(req: RunRequest, onEvent: (ev: string, data: any) => void): () => void {
  const q = new URLSearchParams({ shield: req.shield });
  if (req.scenario) q.set("scenario", req.scenario);
  if (req.message) q.set("message", req.message);
  if (req.payload !== undefined) q.set("payload", req.payload);
  const es = new EventSource(`/api/run/stream?${q}`);
  for (const ev of EVENTS) {
    es.addEventListener(ev, (e) => {
      const data = (e as MessageEvent).data;
      if (ev === "error" && !data) return; // connection error, handled below
      onEvent(ev, JSON.parse(data));
      if (ev === "done") es.close();
    });
  }
  // EventSource reconnects by default, which would START THE RUN AGAIN. Never let it.
  es.onerror = (e) => {
    if ((e as MessageEvent).data) return; // the server's own "error" event also lands here; handled above
    if (es.readyState !== EventSource.CLOSED) {
      es.close();
      onEvent("error", { message: "Lost connection to the assistant. Nothing more will be sent." });
      onEvent("done", {});
    }
  };
  return () => es.close();
}

export const newRun = (req: RunRequest, message: string): Run => ({
  key: "k-" + Math.random().toString(36).slice(2),
  id: "",
  scenario: req.payload !== undefined ? "LIVE" : req.scenario ?? "custom",
  message,
  shield: req.shield,
  plannerMode: "",
  llmMode: "",
  scripted: false,
  pills: [],
  calls: [],
  taint: [],
  outbox: [],
  thinking: true,
  status: "running",
});

/** Plain-language helpers: the UI never shows tool names or JSON outside "details". */
export const TOOL_PLAIN: Record<string, string> = {
  list_inbox: "Look through the inbox",
  read_email: "Read an email",
  search_docs: "Search documents",
  read_doc: "Open a document",
  read_vault: "Open the password vault",
  send_email: "Send an email",
  fetch_url: "Open a web address",
  delete_files: "Delete files",
};

export function describeCall(c: { tool: string; args: Record<string, unknown> | string }): string {
  const a = typeof c.args === "object" && c.args ? c.args : {};
  const base = TOOL_PLAIN[c.tool] ?? `Unknown action "${c.tool}"`;
  if (c.tool === "send_email" && a.to) return `${base} to ${a.to}`;
  if (c.tool === "read_email" && a.id !== undefined) return `${base} (#${a.id})`;
  if (c.tool === "read_doc" && a.name) return `${base}: ${a.name}`;
  if (c.tool === "search_docs" && a.query) return `${base} for “${a.query}”`;
  if (c.tool === "read_vault" && a.key) return `${base} (${a.key})`;
  if (c.tool === "fetch_url" && a.url) return `${base}: ${a.url}`;
  if (c.tool === "delete_files" && a.path) return `${base} in ${a.path}`;
  return base;
}

/** A non-ALLOW decision proposed after untrusted content was read counts as an attack attempt,
 *  except a secret the user explicitly asked to send (vault open in the contract): that is a prompt. */
export const isAttack = (c: Call, run: Run) =>
  !!c.decision && c.decision.verdict !== "ALLOW" && c.afterTaint &&
  !(c.decision.rule_id === "SECRET_TO_SINK" && run.pills.includes("Vault: open"));
export const wasStopped = (c: Call) => !c.executed;
