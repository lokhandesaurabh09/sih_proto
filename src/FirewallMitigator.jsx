import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { Ban, Download, PlugZap, Server, ShieldCheck, SlidersHorizontal } from "lucide-react";

/* ═══════════════════════════════════════════════════════════════════
   DYNAMIC FIREWALL MITIGATION — PREDICTION-AWARE ACL ENGINE
   Human-in-the-loop: world model drafts → operator approves → armed.
   ═══════════════════════════════════════════════════════════════════ */

/* ── Input validation (garbage-proof ACL builder) ── */
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

const isValidAddress = (raw) => {
  if (typeof raw !== "string") return false;
  const v = raw.trim();
  if (!v) return false; // empty field = not yet filled — keep DEPLOY disabled
  if (v === "any" || v === "0.0.0.0/0") return true;
  const [ip, cidr] = v.split("/");
  if (!IPV4_RE.test(ip)) return false;
  if (cidr === undefined) return true;
  const p = Number(cidr);
  return Number.isInteger(p) && p >= 0 && p <= 32;
};

const isValidPort = (raw) => {
  if (raw === "any") return true;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
};

/* ── Seed ACL (static baseline) ── */
let fwSeq = 3; // next manual rule id suffix (FW-0004…)

const SEED_RULES = [
  { id: "FW-0001", action: "ALLOW", src: "0.0.0.0/0", dst: "10.0.5.0/24", port: "any", proto: "any", source: "BASELINE", hits: 0, enabled: true },
  { id: "FW-0002", action: "ALERT", src: "185.199.110.23", dst: "10.0.5.23", port: 22, proto: "tcp", source: "WATCHLIST", hits: 3, enabled: true },
  { id: "FW-0003", action: "DROP", src: "91.240.118.4", dst: "10.0.5.23", port: 22, proto: "tcp", source: "SOC-OPERATOR", hits: 1, enabled: true },
];

const ACTION_TONES = {
  DROP: { pill: "border-rose-500/60 bg-rose-500/15 text-rose-300", dot: "bg-rose-500" },
  ALERT: { pill: "border-amber-400/40 bg-amber-500/10 text-amber-300", dot: "bg-amber-400" },
  ALLOW: { pill: "border-emerald-400/40 bg-emerald-500/10 text-emerald-300", dot: "bg-emerald-400" },
};

const SOURCE_TONES = {
  "AI-MITIGATOR": "border-purple-400/40 bg-purple-500/10 text-purple-300",
  "SOC-OPERATOR": "border-cyan-400/30 bg-cyan-500/10 text-cyan-300",
  WATCHLIST: "border-amber-400/30 bg-amber-500/5 text-amber-300",
  BASELINE: "border-slate-600 bg-slate-800/60 text-slate-400",
};

const stamp = () => new Date().toISOString().replaceAll("-", "").replaceAll(":", "").replaceAll("T", "").slice(0, 14);

/* ═══════════════════════════════════════════════  subcomponents  ══ */

function ToggleSwitch({ rule, on, onToggle }) {
  return (
    <button
      onClick={() => onToggle(rule)}
      aria-label={`toggle ${rule.id}`}
      title={on ? `${rule.id} ENABLED` : `${rule.id} DISABLED`}
      className={`relative inline-flex h-4 w-8 cursor-pointer items-center rounded-full border transition-all active:scale-90 ${
        on
          ? "border-emerald-400/50 bg-emerald-500/30 hover:border-emerald-300/80 hover:bg-emerald-500/40"
          : "border-slate-700 bg-slate-800 hover:border-slate-500 hover:bg-slate-700"
      }`}
    >
      <span
        className={`inline-block h-2.5 w-2.5 transform rounded-full transition-transform ${
          on ? "translate-x-[15px] bg-emerald-400" : "translate-x-[2px] bg-slate-500"
        }`}
      />
    </button>
  );
}

function RuleRow({ rule, hitCount, state, onToggle }) {
  const at = ACTION_TONES[rule.action] || ACTION_TONES.ALLOW;
  const st = SOURCE_TONES[rule.source] || SOURCE_TONES.BASELINE;
  const isDrafted = rule.auto && state === "drafted";
  const isArmed = rule.auto && state === "armed";

  return (
    <motion.tr
      initial={{ opacity: 0, y: -14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.32, ease: "easeOut" }}
      className={`border-b border-slate-800/60 transition-colors hover:bg-slate-800/50 ${!rule.enabled ? "opacity-45" : ""}`}
    >
      <td className="whitespace-nowrap px-3 py-2 font-bold text-slate-300">
        <span className="flex items-center gap-2">
          {isArmed && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />}
          {isDrafted && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-400" />}
          <span className={isDrafted ? "text-amber-300" : ""}>{rule.id}</span>
        </span>
      </td>
      <td className="px-3 py-2">
        <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-bold tracking-wider ${at.pill}`}>
          <span className={`h-1 w-1 rounded-full ${at.dot}`} />
          {rule.action}
        </span>
      </td>
      <td className="whitespace-nowrap px-3 py-2 text-slate-300">
        <span className="text-slate-500">{rule.src}</span>
        <span className="mx-1 text-slate-600">→</span>
        <span className="font-bold">{rule.dst}</span>
        <span className="text-slate-600">:{rule.port}</span>
      </td>
      <td className="px-3 py-2 text-center text-slate-400 uppercase">{rule.proto}</td>
      <td className="px-3 py-2 text-right font-bold tabular-nums text-slate-200">{String(hitCount).padStart(3, "0")}</td>
      <td className="px-3 py-2">
        <span className={`inline-flex rounded border px-1.5 py-0.5 text-[9px] font-bold tracking-wider ${st}`}>
          {rule.source}
        </span>
      </td>
      <td className="px-3 py-2 text-right">
        {isDrafted ? (
          <span className="inline-flex items-center gap-1 whitespace-nowrap font-mono text-[9px] font-bold text-amber-300">
            <span className="h-1 w-1 animate-pulse rounded-full bg-amber-400" /> PENDING
          </span>
        ) : (
          <ToggleSwitch rule={rule} on={rule.enabled} onToggle={onToggle} />
        )}
      </td>
    </motion.tr>
  );
}

function DraftActions({ rule, onApprove, onDismiss }) {
  return (
    <motion.tr
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: "easeOut" }}
      className="border-b border-amber-400/20 bg-amber-500/[0.06]"
    >
      <td colSpan={7} className="px-3 py-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="inline-flex items-center gap-2 font-mono text-[10px] text-amber-300">
            <PlugZap className="h-3.5 w-3.5" />
            AI-GENERATED COUNTERMEASURE — DROP {rule.src} → {rule.dst}:{rule.port} {rule.proto}/{rule.port}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onApprove}
              className="inline-flex items-center gap-1.5 rounded-md border border-emerald-400/50 bg-emerald-500/20 px-3 py-1.5 font-mono text-[10px] font-bold text-emerald-300 transition-all hover:bg-emerald-500/40 hover:shadow-[0_0_16px_rgba(52,211,153,0.4)] active:scale-[0.97]"
            >
              <ShieldCheck className="h-3.5 w-3.5" /> [ APPROVE &amp; ARM ]
            </button>
            <button
              onClick={onDismiss}
              className="rounded-md border border-slate-600 bg-slate-800/80 px-3 py-1.5 font-mono text-[10px] font-bold text-slate-400 transition-colors hover:border-rose-500/50 hover:text-rose-300 active:scale-[0.97]"
            >
              [ DISMISS ]
            </button>
          </div>
        </div>
      </td>
    </motion.tr>
  );
}

function BuilderField({ label, value, onChange, placeholder, error }) {
  return (
    <div>
      <label className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</label>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        spellCheck={false}
        className={`w-full rounded-md border bg-slate-950/80 px-2 py-1.5 text-[11px] text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-400/50 ${
          error ? "border-rose-500/70 hover:border-rose-400" : "border-slate-700 hover:border-slate-600"
        }`}
      />
      {error && <p className="mt-0.5 font-mono text-[10px] font-bold text-rose-400">⚠ {error}</p>}
    </div>
  );
}

function MiniStat({ label, value, tone, sub }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</div>
      <div className={`mt-1 font-mono text-sm font-bold tabular-nums ${tone}`}>{value}</div>
      {sub && <div className="mt-0.5 font-mono text-[10px] text-slate-500">{sub}</div>}
    </div>
  );
}

/* ═══════════════════════════════════════════════  main component  ══ */

export default function FirewallMitigator({
  alertActive,
  attack,            // { src, dst, port, proto, worldP }
  requestedHits = {},// { [ruleId]: liveDrops } — display-only mirror of App tick counters
  onRuleEvent,       // (text) → injects a CII-SOC-ENGINE system row into the feed
  onBlockRuleList,   // (rules) → syncs the App packet-matcher ref (synchronous read)
  onMitigationState, // ("standby"|"drafted"|"armed"|"revoked") → hero chart branching
}) {
  /* ── state ── */
  const [fwRules, setFwRules] = useState(SEED_RULES);
  const [mitState, setMitState] = useState("standby"); // standby | drafted | armed | revoked
  const [builder, setBuilder] = useState({ src: "45.83.12.7", dst: "10.0.5.23", port: "22", proto: "tcp", action: "DROP" });
  const [deployError, setDeployError] = useState(null);
  const [exported, setExported] = useState(false);
  const autoFiredRef = useRef(false); // StrictMode-safe single-draft guard

  /* ── sync enabled DROP rules to the App packet-matcher (ref) ──
     HUMAN-IN-THE-LOOP ORDERING: a PENDING AI draft is NEVER enforced.
     The matcher only carries rules AFTER operator APPROVE & ARM (or RE-ARM),
     so enforcement never precedes human authorization. */
  useEffect(() => {
    const drops = fwRules
      .filter((r) => r.enabled && r.action === "DROP")
      .filter((r) => !(r.auto && mitState === "drafted"))
      .map((r) => ({ id: r.id, src: r.src, action: r.action, enabled: true }));
    onBlockRuleList(drops);
  }, [fwRules, mitState, onBlockRuleList]);

  /* ── mirror mitigation state to App (hero chart branches on it) ── */
  useEffect(() => {
    onMitigationState(mitState);
  }, [mitState, onMitigationState]);

  /* ── human-in-the-loop: world model fires → AI drafts DROP rule ── */
  useEffect(() => {
    if (!alertActive || autoFiredRef.current) return;
    autoFiredRef.current = true;
    const draft = {
      id: "FW-AUTO-001",
      action: "DROP",
      src: attack.src,
      dst: attack.dst,
      port: attack.port,
      proto: attack.proto,
      source: "AI-MITIGATOR",
      hits: 0,
      enabled: true,
      auto: true,
    };
    setFwRules((prev) => [draft, ...prev]);
    setMitState("drafted");
    onRuleEvent(`AI-MITIGATOR :: DRAFT ${draft.id} ${draft.action} ${draft.src} → ${draft.dst}:${draft.port} ${draft.proto}/${draft.port}`);
  }, [alertActive, attack, onRuleEvent]);

  /* ── operator actions ── */
  const handleApprove = () => {
    setMitState("armed");
    onRuleEvent(`SOC :: APPROVE FW-AUTO-001 — ARMED :: DROP ${attack.src} → ${attack.dst}:${attack.port} ${attack.proto}/${attack.port}`);
  };

  const handleDismiss = () => {
    setFwRules((prev) => prev.filter((r) => !r.auto));
    setMitState("standby");
    onRuleEvent("AI-MITIGATOR :: DRAFT REJECTED FW-AUTO-001 — NO ACTION TAKEN");
  };

  const handleToggle = (rule) => {
    const nextOn = !rule.enabled;
    if (rule.auto && mitState === "drafted") {
      setFwRules((prev) => prev.filter((r) => r.id !== rule.id));
      setMitState("standby");
      onRuleEvent("AI-MITIGATOR :: DRAFT REJECTED FW-AUTO-001 (operator toggle)");
      return;
    }
    setFwRules((prev) => prev.map((r) => (r.id === rule.id ? { ...r, enabled: nextOn } : r)));
    if (rule.auto) setMitState(nextOn ? "armed" : "revoked");
    onRuleEvent(`SOC :: ${nextOn ? "ENABLE" : "DISABLE"} ${rule.id}${rule.auto && !nextOn ? " — mitigation overridden" : ""}`);
  };

  const reArm = () => {
    const auto = fwRules.find((r) => r.auto);
    if (auto) handleToggle(auto);
  };

  /* ── ACL builder ── */
  const handleBuilderChange = (key, value) => setBuilder((b) => ({ ...b, [key]: value }));

  const builderErrors = useMemo(
    () => ({
      src: isValidAddress(builder.src) ? null : "INVALID IPv4/CIDR",
      dst: isValidAddress(builder.dst) ? null : "INVALID IPv4/CIDR",
      port: isValidPort(builder.port) ? null : "INVALID 1-65535",
    }),
    [builder.src, builder.dst, builder.port]
  );
  const atCap = fwRules.length >= 12;

  const handleDeploy = () => {
    if (atCap) { setDeployError("RULE LIMIT REACHED (12) — disable a rule first"); return; }
    if (builderErrors.src || builderErrors.dst || builderErrors.port) { setDeployError("VALIDATE FIELDS BEFORE DEPLOY"); return; }
    const id = `FW-${String(++fwSeq).padStart(4, "0")}`;
    const dup = fwRules.find(
      (r) => r.action === "DROP" && r.enabled && r.src === builder.src.trim() && r.dst === builder.dst.trim() && String(r.port) === String(builder.port)
    );
    if (dup) { setDeployError(`RULE EXISTS FOR SOURCE ${builder.src.trim()} (${dup.id})`); return; }
    const rule = {
      id,
      action: builder.action,
      src: builder.src.trim(),
      dst: builder.dst.trim(),
      port: builder.port === "any" ? "any" : Number(builder.port),
      proto: builder.proto,
      source: "SOC-OPERATOR",
      hits: 0,
      enabled: true,
    };
    setFwRules((prev) => [rule, ...prev]);
    onRuleEvent(`SOC :: ACL-ADD ${id} ${rule.action} ${rule.src} → ${rule.dst}:${rule.port} ${rule.proto}`);
    setDeployError(null);
    setBuilder((b) => ({ ...b, src: "45.83.12.7", port: "22" }));
  };

  /* ── policy export (Blob download) ── */
  const totalBlocked = Object.values(requestedHits).reduce((a, b) => a + b, 0);

  const handleExport = () => {
    const fileStamp = stamp();
    const payload = {
      schema: "cii-acl-policy/v1",
      exported_at: new Date().toISOString(),
      engine: "CII Predictive SOC Engine · Prediction-Aware ACL v1",
      provenance: "local · air-gapped · no cloud round-trip",
      assessment: {
        attack: { src: attack.src, dst: attack.dst, port: attack.port, proto: attack.proto },
        world_model_p: attack.worldP,
        mitigation_state: mitState,
        attack_blocked_total: totalBlocked,
      },
      rules: fwRules.map((r) => ({
        id: r.id,
        enabled: r.enabled,
        action: r.action,
        src: r.src,
        dst: r.dst,
        port: r.port,
        proto: r.proto,
        source: r.source,
        auto_generated: Boolean(r.auto),
        hits: (r.hits || 0) + (requestedHits[r.id] || 0),
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cii-acl-policy-${fileStamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    onRuleEvent(`SOC::POLICY-EXPORT cii-acl-policy-${fileStamp}.json (${fwRules.length} rules)`);
    setExported(true);
    window.setTimeout(() => setExported(false), 1800);
  };

  /* ── derived visuals ──
     sparkline = LIVE session drops per rule (accurate "blocked now" readout);
     the rules table's Hit column adds the historical seed (`r.hits`) so
     cumulative totals stay truthful. Both + Blocked pkts share `requestedHits`,
     so a counter increment always matches a bar bump on the credited rule. */
  const hitsData = fwRules.map((r) => ({
    id: r.id,
    hits: requestedHits[r.id] || 0,
    action: r.action,
  }));
  const armedRules = fwRules.filter((r) => r.enabled).length;

  const CHIP = {
    standby: { label: "STANDBY", dot: "animate-pulse bg-slate-400", cls: "border-slate-700 bg-slate-800/80 text-slate-400" },
    drafted: { label: "DRAFT PENDING", dot: "animate-pulse bg-amber-400", cls: "border-amber-400/50 bg-amber-500/15 text-amber-300" },
    armed: { label: "ARMED", dot: "animate-pulse bg-emerald-400", cls: "animate-glow-pulse border-emerald-400/50 bg-emerald-500/15 text-emerald-300" },
    revoked: { label: "MITIGATION REVOKED", dot: "animate-pulse bg-rose-500", cls: "border-rose-500/60 bg-rose-500/15 text-rose-300" },
  }[mitState];

  const statusLines = {
    standby: { main: "STANDBY", sub: "world-model monitoring · no countermeasure", mainTone: "text-slate-300" },
    drafted: { main: "DRAFT PENDING", sub: "FW-AUTO-001 awaiting operator approval", mainTone: "text-amber-300" },
    armed: { main: "ACTIVE", sub: "FW-AUTO-001 enforced @ edge · drops live", mainTone: "text-emerald-300" },
    revoked: { main: "REVOKED", sub: "attack traffic re-entered — risk climbing", mainTone: "text-rose-300" },
  }[mitState];

  return (
    <div className="relative flex flex-col overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70 shadow-[0_0_40px_rgba(0,0,0,0.25)] backdrop-blur-sm">
      {/* ── header ── */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-900/60 px-4 py-3">
        <div className="flex items-center gap-2">
          <Ban className="h-4 w-4 text-rose-400" />
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300">Dynamic Firewall Mitigation</h2>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden font-mono text-[10px] text-slate-500 md:inline">PREDICTION-AWARE ACL ENGINE</span>
          <span className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-[10px] font-bold tracking-wider ${CHIP.cls}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${CHIP.dot}`} />
            {CHIP.label}
          </span>
        </div>
      </div>

      {/* ── body grid ── */}
      <div className="grid flex-1 grid-cols-1 gap-4 p-4 xl:grid-cols-3">
        {/* left — rules table + quick stats */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          <div className="overflow-hidden rounded-lg border border-slate-800">
            <div className="scroll-soc max-h-[280px] overflow-auto">
              <table className="w-full min-w-[760px] border-collapse font-mono text-[11px]">
                <thead className="sticky top-0 z-10">
                  <tr className="border-b border-slate-800 bg-slate-900 text-left text-[9px] uppercase tracking-[0.2em] text-slate-500">
                    <th className="px-3 py-2">Rule</th>
                    <th className="px-3 py-2">Action</th>
                    <th className="px-3 py-2">Source → Destination</th>
                    <th className="px-3 py-2 text-center">Proto</th>
                    <th className="px-3 py-2 text-right">Hits</th>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2 text-right">State</th>
                  </tr>
                </thead>
                <tbody>
                  {fwRules.map((r) => (
                    <Fragment key={r.id}>
                      <RuleRow
                        rule={r}
                        hitCount={(r.hits || 0) + (requestedHits[r.id] || 0)}
                        state={mitState}
                        onToggle={handleToggle}
                      />
                      {r.auto && mitState === "drafted" && (
                        <DraftActions rule={r} onApprove={handleApprove} onDismiss={handleDismiss} />
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* quick stats */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <MiniStat
              label="Blocked pkts"
              value={totalBlocked === 0 ? "···" : String(totalBlocked).padStart(3, "0")}
              tone={totalBlocked === 0 ? "text-slate-700" : "text-emerald-300"}
              sub="live · sum of per-rule bars"
            />
            <MiniStat label="Armed rules" value={`${armedRules}/${fwRules.length}`} tone="text-cyan-300" sub="enabled / total" />
            <MiniStat
              label="Curr risk"
              value={`${((attack.worldP || 0) * 100).toFixed(1)}%`}
              tone="text-rose-400"
              sub="world-model P"
            />
            <MiniStat
              label="Forecast"
              value={mitState === "armed" ? "0.88→0.21" : mitState === "revoked" ? "0.88→0.95↑" : "—"}
              tone="text-slate-300"
              sub="post-mitigation"
            />
          </div>
        </div>

        {/* right rail */}
        <div className="flex flex-col gap-4 xl:col-span-1">
          {/* drop activity sparkline */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Drop Activity by Rule</span>
              <Server className="h-3 w-3 text-rose-400/70" />
            </div>
            <div className="relative h-[88px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={hitsData} margin={{ top: 4, right: 4, left: 4, bottom: 0 }}>
                  <XAxis
                    dataKey="id"
                    tick={{ fill: "#64748b", fontSize: 8.5, fontFamily: "JetBrains Mono, monospace" }}
                    axisLine={false}
                    tickLine={false}
                    interval={0}
                  />
                  <YAxis hide />
                  <Bar dataKey="hits" radius={[3, 3, 0, 0]} isAnimationActive animationDuration={600}>
                    {hitsData.map((tick) => (
                      <Cell key={tick.id} fill={tick.action === "DROP" ? "#FF3D00" : "#FFAB00"} />
                    ))}
                    <LabelList
                      dataKey="hits"
                      position="top"
                      formatter={(v) => (v > 0 ? String(v).padStart(3, "0") : "")}
                      style={{ fill: "#94a3b8", fontSize: 9, fontWeight: 700, fontFamily: "JetBrains Mono, monospace" }}
                    />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              {totalBlocked === 0 && (
                <div className="pointer-events-none absolute inset-0 flex items-center justify-center font-mono text-[10px] text-slate-700">
                  NO DROP ACTIVITY · AWAITING DETECTION
                </div>
              )}
            </div>
          </div>

          {/* mitigation status readout */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Mitigation Status</span>
              <span
                className={`inline-flex h-1.5 w-1.5 rounded-full ${
                  mitState === "armed"
                    ? "animate-pulse bg-emerald-400"
                    : mitState === "drafted"
                    ? "animate-pulse bg-amber-400"
                    : mitState === "revoked"
                    ? "animate-pulse bg-rose-500"
                    : "animate-pulse bg-slate-400"
                }`}
              />
            </div>
            <div className={`mt-1 font-mono text-lg font-bold ${statusLines.mainTone}`}>{statusLines.main}</div>
            <div className="font-mono text-[10px] text-slate-500">{statusLines.sub}</div>
            {mitState === "revoked" && (
              <button
                onClick={reArm}
                className="mt-2 inline-flex w-full items-center justify-center gap-1.5 rounded-md border border-emerald-400/50 bg-emerald-500/15 px-2 py-1.5 font-mono text-[10px] font-bold text-emerald-300 transition-all hover:bg-emerald-500/30 active:scale-[0.98]"
              >
                <ShieldCheck className="h-3.5 w-3.5" /> [ RE-ARM FW-AUTO-001 ]
              </button>
            )}
          </div>

          {/* export policy */}
          <button
            onClick={handleExport}
            className="group inline-flex items-center justify-center gap-2 rounded-md border border-cyan-400/40 bg-cyan-500/10 px-3 py-2.5 font-mono text-[10px] font-bold tracking-wider text-cyan-300 transition-all hover:border-cyan-400/70 hover:bg-cyan-500/20 hover:shadow-[0_0_20px_rgba(0,229,255,0.25)] active:scale-[0.98]"
          >
            <Download className="h-3.5 w-3.5 transition-transform group-hover:-translate-y-0.5" />
            {exported ? "EXPORTED ✓" : "EXPORT POLICY → JSON"}
          </button>
        </div>
      </div>

      {/* ── ACL rule builder (full width strip) ── */}
      <div className="border-t border-slate-800/80 bg-slate-950/50 px-4 pb-4 pt-3">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-widest text-slate-300">
            <SlidersHorizontal className="h-3 w-3 text-cyan-400" /> Rules — manual edge ACL builder
          </span>
          {deployError && (
            <span className="inline-flex items-center gap-1.5 font-mono text-[9px] font-bold text-rose-400">
              <Ban className="h-3 w-3" /> {deployError}
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 gap-2 font-mono text-[11px] sm:grid-cols-3 lg:grid-cols-5">
          <BuilderField
            label="Source IP"
            value={builder.src}
            onChange={(v) => handleBuilderChange("src", v)}
            placeholder="45.83.12.7"
            error={builderErrors.src}
          />
          <BuilderField
            label="Dest IP"
            value={builder.dst}
            onChange={(v) => handleBuilderChange("dst", v)}
            placeholder="10.0.5.23"
            error={builderErrors.dst}
          />
          <BuilderField
            label="Port"
            value={builder.port}
            onChange={(v) => handleBuilderChange("port", v)}
            placeholder="22 | any"
            error={builderErrors.port}
          />
          <div>
            <label className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-400">Proto</label>
            <select
              value={builder.proto}
              onChange={(e) => handleBuilderChange("proto", e.target.value)}
              className="w-full cursor-pointer rounded-md border border-slate-700 bg-slate-950/80 px-2 py-1.5 text-[11px] text-slate-200 outline-none transition-colors hover:border-slate-600 focus:border-cyan-400/50"
            >
              {["tcp", "udp", "icmp", "any"].map((p) => (
                <option key={p} value={p} className="bg-slate-900">
                  {p}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-400">Action</label>
            <select
              value={builder.action}
              onChange={(e) => handleBuilderChange("action", e.target.value)}
              className="w-full cursor-pointer rounded-md border border-slate-700 bg-slate-950/80 px-2 py-1.5 text-[11px] text-slate-200 outline-none transition-colors hover:border-slate-600 focus:border-cyan-400/50"
            >
              {["DROP", "ALLOW"].map((a) => (
                <option key={a} value={a} className="bg-slate-900">
                  {a}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
          <span className="min-w-0 font-mono text-[9px] leading-relaxed text-slate-600">
            IPv4 / CIDR source · any IP or port accepted · pre-loaded from live threat profile · ACLs enforce only after operator approval
            {atCap && (
              <span className="font-bold text-amber-300"> · RULE LIMIT 12 — {fwRules.length} ACTIVE</span>
            )}
          </span>
          <button
            onClick={handleDeploy}
            disabled={Boolean(builderErrors.src || builderErrors.dst || builderErrors.port) || atCap}
            title={
              atCap
                ? "Rule limit reached (12) — disable a rule first"
                : Boolean(builderErrors.src || builderErrors.dst || builderErrors.port)
                ? "All fields must be valid before deploying"
                : "Deploy this ACL rule"
            }
            className="inline-flex items-center justify-center gap-1.5 rounded-md bg-cyan-500/90 px-4 py-2 font-mono text-[10px] font-bold text-slate-950 shadow-[0_0_10px_rgba(0,229,255,0.2)] transition-all hover:bg-cyan-400 hover:shadow-[0_0_16px_rgba(0,229,255,0.35)] disabled:cursor-not-allowed disabled:bg-slate-800/80 disabled:text-slate-600 disabled:shadow-none active:scale-[0.98]"
          >
            <PlugZap className="h-3.5 w-3.5" /> DEPLOY ACL
          </button>
        </div>
      </div>
    </div>
  );
}



