import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ReferenceLine,
  BarChart, Bar, Cell, LabelList,
} from "recharts";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity, Check, Cpu, Crosshair, Fingerprint, Gauge, Lock, Network,
  Radio, Shield, ShieldCheck, Siren, Skull, Target, Terminal, Timer, Zap,
} from "lucide-react";
import FirewallMitigator from "./FirewallMitigator.jsx";

/* ══════════════════════════════════════════════════════════════════
   CII PREDICTIVE SOC ENGINE — SMART INDIA HACKATHON PROTOTYPE
   Scenario: "The SSH Brute Force" · Air-gapped local inference sim
   ══════════════════════════════════════════════════════════════════ */

const THRESHOLD = 0.75;   // Alert threshold on P(infiltration)
const TICK_MS = 2200;     // Simulation tick interval (ms)
const ALERT_VISIBLE_MS = 5000;              // alert card stays up for 5s…
const ALERT_FLASH_MS = 1100;                // …then flashes and auto-dismisses
const ATTACKER_IP = "185.199.110.23";       // threat-source used by the mitigation module

/* ── Post-mitigation forecast (hero-chart extension after ARMED / REVOKED) ── */
const MITIGATION_FORECAST = [
  { time: "10:01:30", projected: 0.72 },
  { time: "10:01:45", projected: 0.55 },
  { time: "10:02:00", projected: 0.38 },
  { time: "10:02:15", projected: 0.21 },
];

/* ── Chart Data (Timeline) ── */
const SCENARIO_TIMELINE = [
  { time: "10:00:00", world_model: 0.08, baseline: 0.05 },
  { time: "10:00:15", world_model: 0.12, baseline: 0.06 },
  { time: "10:00:30", world_model: 0.35, baseline: 0.10 },
  { time: "10:00:45", world_model: 0.48, baseline: 0.11 },
  { time: "10:01:00", world_model: 0.62, baseline: 0.25 },
  { time: "10:01:15", world_model: 0.88, baseline: 0.40 },
];

/* ── Live Traffic Feed Data ── */
const SCENARIO_FEED = [
  { time: "10:01:12", src: "10.0.5.15", dst: "10.0.5.8", port: 443, flags: "ACK, PSH", status: "normal" },
  { time: "10:01:13", src: "185.199.110.23", dst: "10.0.5.23", port: 22, flags: "SYN", status: "suspicious" },
  { time: "10:01:13", src: "185.199.110.23", dst: "10.0.5.23", port: 22, flags: "SYN", status: "malicious" },
];

/* ── SHAP Feature Data ── */
const SHAP_FEATURES = [
  { feature: "tcp_syn_flag_count", impact: 0.42 },
  { feature: "iat_variance", impact: 0.28 },
  { feature: "dst_port_entropy", impact: 0.18 },
];

/* ── Alert Trigger Payload (fires at 10:01:15 / > 0.75) ── */
const ALERT_PAYLOAD = {
  severity: "CRITICAL",
  stage: "TA0001 (Initial Access)",
  desc: "High-velocity state transition predicted. Anomalous SSH volumetric spike.",
  target: "10.0.5.23",
};

/* ── MITRE ATT&CK kill-chain tracker ── */
const MITRE_STAGES = [
  { code: "TA0043", name: "Reconnaissance", status: "cleared" },
  { code: "TA0001", name: "Initial Access", status: "active" },
  { code: "TA0002", name: "Execution", status: "pending" },
  { code: "TA0003", name: "Persistence", status: "pending" },
  { code: "TA0008", name: "Lateral Movement", status: "pending" },
];

/* ── Ambient background traffic generator (post-scenario) ── */
let rowUid = 0;
let ambientSeq = 0;
const AMBIENT_SRCS = ["10.0.5.14", "10.0.5.19", "10.0.5.21", "172.16.4.11", "192.168.12.3"];
const AMBIENT_DSTS = ["10.0.5.8", "10.0.5.9", "10.0.5.12", "10.0.5.23"];
const AMBIENT_FLAGS = ["ACK", "ACK, PSH", "ACK, FIN", "SYN, ACK", "PSH, ACK"];
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

function fmtClock(totalSec) {
  const h = String(Math.floor(totalSec / 3600) % 24).padStart(2, "0");
  const m = String(Math.floor(totalSec / 60) % 60).padStart(2, "0");
  const s = String(totalSec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function makeAmbientPacket(clockSec, armedSrc = null) {
  ambientSeq += 1;
  const r = Math.random();
  const status = r < 0.82 ? "normal" : r < 0.93 ? "suspicious" : "malicious";
  const hostile = status !== "normal";
  // Post-approval the simulation converges hostile probes on the predicted source:
  // the armed FW-AUTO-001 rule then cuts EVERY one of them — a visible, provable
  // drop (revocation / standby keeps the full multi-source attacker pool).
  const src = hostile && armedSrc ? armedSrc : pick(hostile ? ["185.199.110.23", "45.83.12.7", "91.240.118.4"] : AMBIENT_SRCS);
  return {
    time: fmtClock(clockSec + ambientSeq),
    src,
    dst: hostile ? pick(["10.0.5.23"]) : pick(AMBIENT_DSTS),
    port: hostile ? 22 : pick([443, 53, 8080, 3306, 22]),
    flags: hostile ? pick(["SYN", "SYN, ACK", "SYN"]) : pick(AMBIENT_FLAGS),
    status,
  };
}

/* ══════════════════════════════ UI BUILDING BLOCKS ══════════════════════════════ */

function Panel({ title, icon: Icon, accent = "text-cyan-400", right, children }) {
  return (
    <div className="relative flex h-full flex-col overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70 shadow-[0_0_40px_rgba(0,0,0,0.25)] backdrop-blur-sm">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-900/60 px-4 py-3">
        <div className="flex items-center gap-2">
          <Icon className={`h-4 w-4 ${accent}`} />
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300">{title}</h2>
        </div>
        {right}
      </div>
      <div className="flex-1 p-4">{children}</div>
    </div>
  );
}

function Kpi({ label, value, tone = "cyan", sub }) {
  const tones = {
    cyan: "text-cyan-400",
    amber: "text-amber-400",
    rose: "text-rose-500",
    purple: "text-purple-400",
    slate: "text-slate-300",
    emerald: "text-emerald-400",
  };
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</div>
      <div className={`mt-1.5 truncate font-mono text-base font-bold leading-none ${tones[tone]}`}>{value}</div>
      {sub && <div className="mt-1 font-mono text-[10px] text-slate-500">{sub}</div>}
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-950/95 px-3 py-2 font-mono text-[11px] shadow-2xl">
      <div className="mb-1.5 text-slate-400">{label} UTC</div>
      {payload.map((p) => {
        const color = p.stroke || p.color || "#94a3b8";
        return (
          <div key={p.dataKey} className="flex items-center justify-between gap-6">
            <span className="flex items-center gap-1.5" style={{ color }}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
              {p.name}
            </span>
            <span className="font-bold" style={{ color }}>{Number(p.value).toFixed(2)}</span>
          </div>
        );
      })}
    </div>
  );
}

function MitreChain() {
  return (
    <div className="flex flex-col gap-2.5">
      {MITRE_STAGES.map((s, i) => {
        const isCleared = s.status === "cleared";
        const isActive = s.status === "active";
        return (
          <div key={s.code} className="flex items-center gap-3">
            <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md border font-mono text-[11px] font-bold ${
              isActive
                ? "animate-glow-pulse border-purple-400/70 bg-purple-500/15 text-purple-300"
                : isCleared
                ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-400"
                : "border-slate-700 bg-slate-800/60 text-slate-600"
            }`}>
              {isCleared ? <Check className="h-3.5 w-3.5" /> : <span>{String(i + 1).padStart(2, "0")}</span>}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className={`truncate text-xs font-semibold ${isActive ? "text-purple-300" : isCleared ? "text-emerald-300" : "text-slate-500"}`}>
                  {s.name}
                  {isActive && <span className="ml-2 rounded bg-purple-500/20 px-1.5 py-0.5 text-[9px] font-bold text-purple-300">PREDICTED</span>}
                </span>
                <span className="font-mono text-[9px] text-slate-600">{s.code}</span>
              </div>
              <div className="mt-1 h-1 overflow-hidden rounded-full bg-slate-800">
                <div className={`h-full rounded-full transition-all duration-700 ${
                  isCleared ? "w-full bg-emerald-400/70" : isActive ? "w-[70%] animate-pulse bg-purple-400" : "w-0"
                }`} />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ── status → style maps for telemetry rows ── */
const STATUS_STYLES = {
  normal: {
    row: "bg-slate-950/40 text-slate-400",
    time: "text-cyan-400/80",
    pill: "border-cyan-400/25 bg-cyan-500/5 text-cyan-400/90",
    label: "NORMAL",
    bar: "bg-cyan-400/50",
    dot: "bg-cyan-400",
  },
  suspicious: {
    row: "bg-amber-500/[0.07] text-amber-100/90",
    time: "text-amber-400",
    pill: "border-amber-400/40 bg-amber-500/15 text-amber-300",
    label: "SUSPICIOUS",
    bar: "bg-amber-400",
    dot: "bg-amber-400",
  },
  malicious: {
    row: "bg-rose-500/10 text-rose-100",
    time: "text-rose-500",
    pill: "border-rose-500/50 bg-rose-500/20 text-rose-400",
    label: "MALICIOUS",
    bar: "bg-rose-500 shadow-[0_0_8px_rgba(255,61,0,0.6)]",
    dot: "bg-rose-500 animate-pulse",
  },
  drop: {
    row: "bg-rose-500/[0.12] text-rose-100",
    time: "text-rose-400",
    pill: "border-rose-500/70 bg-rose-500/25 text-rose-300",
    label: "FW·DROP",
    bar: "bg-rose-500 shadow-[0_0_8px_rgba(255,61,0,0.7)] animate-pulse",
    dot: "bg-rose-500 animate-pulse",
  },
  system: {
    row: "bg-emerald-500/[0.08] text-emerald-100/90",
    time: "text-emerald-400",
    pill: "border-emerald-400/40 bg-emerald-500/15 text-emerald-300",
    label: "SYSTEM",
    bar: "bg-emerald-400",
    dot: "bg-emerald-400",
  },
};

function TelemetryRow({ row }) {
  const st = STATUS_STYLES[row.status] || STATUS_STYLES.normal;
  return (
    <motion.tr
      initial={{ opacity: 0, y: -14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className={`${st.row} transition-colors hover:bg-slate-800/50`}
    >
      <td className="w-1 px-1 py-2">
        <span className={`block h-6 w-[3px] rounded-full ${st.bar}`} />
      </td>
      <td className="whitespace-nowrap px-4 py-2">
        <span className="flex items-center gap-2">
          <span className={`h-1.5 w-1.5 rounded-full ${st.dot}`} />
          <span className={st.time}>{row.time}</span>
        </span>
      </td>
      <td className="whitespace-nowrap px-4 py-2 text-slate-200">{row.src}</td>
      <td className="whitespace-nowrap px-4 py-2 text-slate-200">{row.dst}</td>
      <td className="px-4 py-2 text-center text-slate-400">{row.port}</td>
      <td className="whitespace-nowrap px-4 py-2 text-violet-300/80">{row.flags}</td>
      <td className="px-4 py-2 text-right">
        <span className={`inline-block rounded border px-2 py-0.5 text-[10px] font-bold tracking-wider ${st.pill}`}>
          {st.label}
        </span>
      </td>
    </motion.tr>
  );
}

export default function App() {
  const [tlIndex, setTlIndex] = useState(2);   // progressive timeline cursor
  const [feedRows, setFeedRows] = useState(() => [{ ...SCENARIO_FEED[0], uid: rowUid++ }]);
  const [sessionTick, setSessionTick] = useState(0);
  const [isolated, setIsolated] = useState(false);
  const [mitigationState, setMitigationState] = useState("standby"); // standby | drafted | armed | revoked
  const [ruleHits, setRuleHits] = useState({}); // { [ruleId]: liveDrops }
  const blockRulesRef = useRef([]);             // synchronous DROP-matcher for the tick (never state)
  const mitigationRef = useRef("standby");      // ref mirror so the tick closure reads latest state
                                                // without resetting the interval (effect deps stay [])
  useEffect(() => {
    mitigationRef.current = mitigationState;
  }, [mitigationState]);

  const baseTimeline = useMemo(() => SCENARIO_TIMELINE.slice(0, tlIndex + 1), [tlIndex]);
  const latest = baseTimeline[baseTimeline.length - 1];
  const alertActive = baseTimeline.some((d) => d.world_model >= THRESHOLD);
  const riskPct = latest.world_model * 100;

  /* timeline branches purely on mitigationState (App-side mirror of FirewallMitigator):
     — armed   : append forecast as `projected` (emerald "P after mitigation" line)
     — revoked : append a climbing world_model regression — attack returns, risk spikes */
  const timeline = useMemo(() => {
    if (mitigationState === "armed") return [...baseTimeline, ...MITIGATION_FORECAST];
    if (mitigationState === "revoked") {
      return [
        ...baseTimeline,
        ...MITIGATION_FORECAST.map((f, i) => ({
          time: f.time,
          world_model: Math.min(0.95, 0.88 + 0.04 * (i + 1)),
          baseline: f.projected,
        })),
      ];
    }
    return baseTimeline;
  }, [baseTimeline, mitigationState]);

  const [alertPhase, setAlertPhase] = useState("idle"); // idle → visible → flash → gone
  const alertHandledRef = useRef(false);

  /* ════════════════════════════════════════════════════════════
     SIMULATED REAL-TIME ENGINE — progressively steps the scenario
     ════════════════════════════════════════════════════════════ */
  useEffect(() => {
    const clockSec = 10 * 3600 + 1 * 60 + 13; // ambient base time 10:01:13
    const id = setInterval(() => {
      setTlIndex((i) => Math.min(i + 1, SCENARIO_TIMELINE.length - 1));
      /* synchronous mitigation check on a ref (never state) so the tick can never
         race an approve/re-arm — no timing gaps between rule sync and match */
      const ambient = makeAmbientPacket(clockSec, mitigationRef.current === "armed" ? ATTACKER_IP : null);
      const match = blockRulesRef.current.find(
        (r) => r.enabled && r.action === "DROP" && (r.src === ambient.src || r.src === "any")
      );
      /* armed DROP rules override the classifier: attack-family traffic (suspicious
         OR malicious) from a blocked source is cut at the edge */
      if (ambient.status !== "normal" && match) {
        ambient.status = "drop";
        ambient.flags = "FW::DROP";
        setRuleHits((h) => ({ ...h, [match.id]: (h[match.id] || 0) + 1 }));
      }
      setFeedRows((prev) => {
        const row =
          prev.length < SCENARIO_FEED.length
            ? { ...SCENARIO_FEED[prev.length], uid: rowUid++ }
            : { ...ambient, uid: rowUid++ };
        return [...prev.slice(-40), row];
      });
      setSessionTick((t) => t + 1);
    }, TICK_MS);
    return () => clearInterval(id);
  }, []);

  /* ════════════════════════════════════════════════════════════
     ALERT LIFECYCLE — hold card 5s, flash-blink, then dismiss
     ════════════════════════════════════════════════════════════ */
  useEffect(() => {
    if (!alertActive || alertHandledRef.current) return;
    alertHandledRef.current = true;
    setAlertPhase("visible");
    const tShow = setTimeout(() => setAlertPhase("flash"), ALERT_VISIBLE_MS);
    const tGone = setTimeout(
      () => setAlertPhase("gone"),
      ALERT_VISIBLE_MS + ALERT_FLASH_MS
    );
    return () => {
      clearTimeout(tShow);
      clearTimeout(tGone);
      alertHandledRef.current = false;
    };
  }, [alertActive]);

  const alertMotion =
    alertPhase === "flash"
      ? {
          animate: {
            opacity: [1, 0.05, 1, 0.05, 1, 0.05, 0],
            scale: [1, 0.97, 1, 0.97, 1, 0.97, 0.96],
          },
          transition: {
            duration: ALERT_FLASH_MS / 1000,
            times: [0, 0.15, 0.3, 0.45, 0.6, 0.75, 1],
            ease: "easeInOut",
          },
        }
      : {
          animate: { opacity: 1, y: 0, scale: 1 },
          transition: { type: "spring", stiffness: 240, damping: 24 },
        };

  const handleIsolate = () => {
    if (isolated) return;
    setIsolated(true);
    setFeedRows((prev) => [
      {
        time: fmtClock(10 * 3600 + 1 * 60 + 17),
        src: "CII-SOC-ENGINE",
        dst: ALERT_PAYLOAD.target,
        port: 22,
        flags: "ACL::BLOCK-ALL",
        status: "system",
        uid: `isolation-${rowUid++}`,
      },
      ...prev,
    ]);
  };

  /* ── FirewallMitigator bridges ── */
  const pushFeedSystemRow = useCallback(
    (text) => {
      setFeedRows((prev) => [
        {
          time: fmtClock(10 * 3600 + 1 * 60 + 15 + sessionTick),
          src: "CII-SOC-ENGINE",
          dst: ALERT_PAYLOAD.target,
          port: 22,
          flags: text,
          status: "system",
          uid: `evt-${rowUid++}`,
        },
        ...prev,
      ]);
    },
    [sessionTick]
  );
  const syncBlockRules = useCallback((rules) => {
    blockRulesRef.current = rules;
  }, []);

  const elapsed = Math.round((sessionTick * TICK_MS) / 1000);
  const riskTone = latest.world_model >= THRESHOLD ? "rose" : latest.world_model >= 0.5 ? "amber" : "cyan";

  return (
    <div className="relative min-h-screen w-full overflow-x-hidden bg-[#0B0F19] text-slate-300 antialiased">
      {/* ambient glow field */}
      <div className="pointer-events-none fixed inset-0 z-0">
        <div className="absolute -left-40 -top-40 h-[28rem] w-[28rem] rounded-full bg-cyan-500/10 blur-[140px]" />
        <div className="absolute -top-24 right-0 h-[24rem] w-[24rem] rounded-full bg-purple-500/10 blur-[140px]" />
        <div className="absolute bottom-0 left-1/3 h-[22rem] w-[22rem] rounded-full bg-rose-500/[0.06] blur-[160px]" />
        <div
          className="absolute inset-0 opacity-40"
          style={{
            backgroundImage: "radial-gradient(rgba(148,163,184,0.09) 1px, transparent 1px)",
            backgroundSize: "26px 26px",
          }}
        />
      </div>

      {/* ═══════════ HEADER ═══════════ */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1700px] flex-wrap items-center justify-between gap-3 px-5 py-3">
          {/* emblem + title */}
          <div className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-400/30 bg-gradient-to-br from-cyan-500/15 to-purple-500/15 shadow-[0_0_20px_rgba(0,229,255,0.2)]">
              <Shield className="h-5 w-5 text-cyan-400" />
              <span className="absolute -bottom-0.5 -right-0.5 flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
              </span>
            </div>
            <div className="leading-tight">
              <h1 className="text-sm font-bold tracking-wide text-slate-50 sm:text-base">CII Predictive SOC Engine</h1>
              <p className="font-mono text-[10px] text-slate-500">AI-Based Network Attack Forecasting Using World Models</p>
            </div>
          </div>

          {/* status cluster */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="animate-glow-pulse inline-flex items-center gap-2 rounded-md border border-emerald-400/40 bg-emerald-500/10 px-3 py-1.5">
              <Lock className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-[10px] font-bold tracking-wider text-emerald-300">STATUS: 100% AIR-GAPPED / LOCAL INFERENCE</span>
            </div>
            <div className="inline-flex items-center gap-2 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono">
              <Timer className="h-3.5 w-3.5 text-purple-400" />
              <span className="text-[10px] text-slate-300">Active State Window: Δt = 10s</span>
            </div>
            <div className="hidden items-center gap-2 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono md:inline-flex">
              <Activity className="h-3.5 w-3.5 text-cyan-400" />
              <span className="text-[10px] text-slate-400">T+{String(elapsed).padStart(2, "0")}s</span>
            </div>
          </div>
        </div>
      </header>

      {/* ═══════════ MAIN GRID ═══════════ */}
      <main className="relative z-10 mx-auto grid max-w-[1700px] grid-cols-1 gap-4 p-4 lg:grid-cols-3">
        {/* ─────── HERO — INFILTRATION PROBABILITY TIMELINE (2/3) ─────── */}
        <section className="lg:col-span-2">
          <Panel
            title="Infiltration Probability Timeline"
            icon={Activity}
            accent="text-cyan-400"
            right={
              <span className="inline-flex items-center gap-1.5 rounded border border-violet-400/30 bg-violet-500/10 px-2 py-1 font-mono text-[10px] text-violet-300">
                <Zap className="h-3 w-3" /> SCENARIO: SSH BRUTE FORCE
              </span>
            }
          >
            {/* KPI strip */}
            <div className="mb-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Kpi
                label="Predicted Risk"
                value={`${riskPct.toFixed(1)}%`}
                tone={riskTone}
                sub={`P(infiltrate) = ${latest.world_model.toFixed(2)}`}
              />
              <Kpi label="Alert Threshold" value={THRESHOLD.toFixed(2)} tone="rose" sub="Latched when exceeded" />
              <Kpi label="Active Model" value="World-Model" tone="cyan" sub="v2.1 · local inference" />
              <Kpi label="Baseline Model" value="LogReg" tone="amber" sub="stateless classifier" />
            </div>

            {/* risk meter */}
            <div className="mb-4">
              <div className="mb-1 flex items-center justify-between font-mono text-[10px] text-slate-500">
                <span className="font-bold uppercase tracking-widest text-slate-400">RISK ENVELOPE</span>
                <span className={latest.world_model >= THRESHOLD ? "font-bold text-rose-400" : "text-cyan-400/80"}>
                  {latest.world_model >= THRESHOLD ? "⚠ OVER THRESHOLD" : "WITHIN THRESHOLD"}
                </span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                <motion.div
                  initial={{ width: 0 }}
                  className={`h-full rounded-full ${
                    latest.world_model >= THRESHOLD
                      ? "bg-gradient-to-r from-amber-400 to-rose-500"
                      : "bg-gradient-to-r from-cyan-500 to-cyan-300"
                  }`}
                  animate={{ width: `${Math.max(4, riskPct)}%` }}
                  transition={{ duration: 0.9, ease: "easeOut" }}
                />
              </div>
              <div className="mt-0.5 flex justify-between font-mono text-[10px] text-slate-500">
                <span>0.00</span>
                <span className="text-rose-500/80">0.75 ⚠</span>
                <span>1.00</span>
              </div>
            </div>

            {/* chart */}
            <div className="relative h-[280px] w-full">
              <div className="pointer-events-none absolute inset-0 z-10 overflow-hidden rounded-lg">
                <div className="animate-scan absolute left-0 top-0 h-full w-1/3 bg-gradient-to-r from-transparent via-cyan-400/[0.06] to-transparent" />
              </div>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={timeline} margin={{ top: 30, right: 14, left: -4, bottom: 0 }}>
                  <defs>
                    <linearGradient id="wmFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.28} />
                      <stop offset="100%" stopColor="#00E5FF" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="blFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#FFAB00" stopOpacity={0.14} />
                      <stop offset="100%" stopColor="#FFAB00" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="mitFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#34d399" stopOpacity={0.22} />
                      <stop offset="100%" stopColor="#34d399" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="4 6" vertical={false} />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "#64748b", fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}
                    axisLine={{ stroke: "#334155" }}
                    tickLine={false}
                    dy={6}
                  />
                  <YAxis
                    domain={[0, 1]}
                    ticks={[0, 0.25, 0.5, 0.75, 1]}
                    tick={{ fill: "#64748b", fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}
                    axisLine={false}
                    tickLine={false}
                    label={{
                      value: "P(INFILT.)",
                      angle: -90,
                      position: "insideLeft",
                      offset: 12,
                      fill: "#475569",
                      fontSize: 9,
                      fontFamily: "JetBrains Mono, monospace",
                    }}
                  />
                  <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#334155", strokeDasharray: "4 4" }} />
                  <Legend
                    verticalAlign="top"
                    height={34}
                    iconType="plainline"
                    iconSize={22}
                    wrapperStyle={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11 }}
                    formatter={(value) => <span style={{ color: "#94a3b8" }}>{value}</span>}
                  />
                  <ReferenceLine
                    y={THRESHOLD}
                    stroke="#FF3D00"
                    strokeDasharray="8 6"
                    strokeWidth={1.6}
                    label={{
                      value: "ALERT THRESHOLD · 0.75",
                      position: "insideTopRight",
                      fill: "#FF3D00",
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "JetBrains Mono, monospace",
                    }}
                  />
                  <Line
                    name="World Model (Predictive)"
                    type="monotone"
                    dataKey="world_model"
                    stroke="#00E5FF"
                    strokeWidth={2.6}
                    fill="url(#wmFill)"
                    dot={{ r: 3.5, fill: "#00E5FF", strokeWidth: 0 }}
                    activeDot={{ r: 6, fill: "#00E5FF", stroke: "#0B0F19", strokeWidth: 2 }}
                    isAnimationActive
                    animationDuration={700}
                  />
                  <Line
                    name="Baseline LogReg"
                    type="monotone"
                    dataKey="baseline"
                    stroke="#FFAB00"
                    strokeWidth={1.6}
                    strokeDasharray="6 4"
                    fill="url(#blFill)"
                    dot={false}
                    activeDot={{ r: 5, fill: "#FFAB00", stroke: "#0B0F19", strokeWidth: 2 }}
                    isAnimationActive
                    animationDuration={700}
                  />
                  {mitigationState === "armed" && (
                    <Line
                      name="P after mitigation"
                      type="monotone"
                      dataKey="projected"
                      stroke="#34d399"
                      strokeWidth={1.8}
                      strokeDasharray="6 4"
                      fill="url(#mitFill)"
                      dot={false}
                      activeDot={{ r: 4, fill: "#34d399", stroke: "#0B0F19", strokeWidth: 2 }}
                      isAnimationActive
                      animationDuration={700}
                    />
                  )}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </Panel>
        </section>
        {/* ─────── THREAT INTELLIGENCE SIDEBAR (1/3) ─────── */}
        <aside className="flex flex-col gap-4 lg:col-span-1">
          {/* MITRE ATT&CK */}
          <Panel title="Current MITRE ATT&CK Stage" icon={Crosshair} accent="text-purple-400">
            <div className="mb-3 flex items-center justify-between gap-2 rounded-lg border border-purple-500/30 bg-purple-500/10 px-3 py-2">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Predicted Stage</div>
                <div className="font-mono text-sm font-bold text-purple-300">{ALERT_PAYLOAD.stage}</div>
              </div>
              <Target className="h-5 w-5 animate-pulse text-purple-400" />
            </div>
            <MitreChain />
            <div className="mt-3 flex items-center justify-between rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-[10px] text-slate-500">
              <span className="flex items-center gap-1.5">
                <Gauge className="h-3 w-3 text-purple-400" /> MODEL CONFIDENCE
              </span>
              <span className="font-bold text-purple-300">94.2%</span>
            </div>
          </Panel>

          {/* SHAP feature importance */}
          <Panel
            title="SHAP Feature Importance — Root Cause"
            icon={Fingerprint}
            accent="text-purple-400"
            right={
              <span className="inline-flex items-center gap-1.5 rounded border border-purple-400/30 bg-purple-500/10 px-2 py-1 font-mono text-[10px] text-purple-300">
                <Cpu className="h-3 w-3" /> XAI · LOCAL
              </span>
            }
          >
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={SHAP_FEATURES} layout="vertical" margin={{ top: 0, right: 34, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="shapGrad0" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#7C4DFF" />
                      <stop offset="100%" stopColor="#00E5FF" />
                    </linearGradient>
                    <linearGradient id="shapGrad1" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#7C4DFF" stopOpacity={0.75} />
                      <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.75} />
                    </linearGradient>
                    <linearGradient id="shapGrad2" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#7C4DFF" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.5} />
                    </linearGradient>
                  </defs>
                  <XAxis type="number" domain={[0, 0.5]} hide />
                  <YAxis
                    type="category"
                    dataKey="feature"
                    width={168}
                    tick={{ fill: "#94a3b8", fontSize: 10.5, fontFamily: "JetBrains Mono, monospace" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Bar dataKey="impact" barSize={18} radius={[0, 5, 5, 0]} isAnimationActive animationDuration={800}>
                    {SHAP_FEATURES.map((d, i) => (
                      <Cell key={d.feature} fill={`url(#shapGrad${i})`} cursor="pointer" />
                    ))}
                    <LabelList
                      dataKey="impact"
                      position="right"
                      formatter={(v) => Number(v).toFixed(2)}
                      style={{ fill: "#a78bfa", fontSize: 11, fontWeight: 700, fontFamily: "JetBrains Mono, monospace" }}
                    />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-[10px] leading-relaxed text-slate-500">
              <span className="text-purple-300/90">▸ ATTRIBUTION:</span> tcp_syn_flag_count is the dominant root-cause
              signal driving the world-model's state transition prediction.
            </div>
          </Panel>
        </aside>
        {/* ─────── DYNAMIC FIREWALL MITIGATION (FULL WIDTH) ─────── */}
        <section className="lg:col-span-3">
          <FirewallMitigator
            alertActive={alertActive}
            attack={{ src: ATTACKER_IP, dst: ALERT_PAYLOAD.target, port: 22, proto: "tcp", worldP: latest.world_model }}
            requestedHits={ruleHits}
            onRuleEvent={pushFeedSystemRow}
            onBlockRuleList={syncBlockRules}
            onMitigationState={setMitigationState}
          />
        </section>
        {/* ─────── LIVE TELEMETRY FEED (FULL WIDTH) ─────── */}
        <section className="lg:col-span-3">
          <Panel
            title="Live Telemetry Feed"
            icon={Radio}
            accent="text-cyan-400"
            right={
              <div className="flex items-center gap-3 font-mono text-[10px] text-slate-500">
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                  LNK-ACTIVE
                </span>
                <span className="hidden sm:inline">{feedRows.length === 0 ? "····" : String(feedRows.length).padStart(4, "0")} PKTS</span>
                <span className="hidden text-slate-600 md:inline">|</span>
                <span className="hidden text-slate-500 md:inline">10G-FABRIC · ETH0</span>
              </div>
            }
          >
            {feedRows.length === 0 && (
              <div className="flex h-32 items-center justify-center gap-2 font-mono text-[11px] text-slate-700">
                <Radio className="h-4 w-4 opacity-60" />
                AWAITING INBOUND TELEMETRY…
              </div>
            )}
            {feedRows.length > 0 && (
              <div className="-m-4 max-h-[300px] scroll-soc overflow-auto">
                <table className="w-full min-w-[820px] border-collapse font-mono text-[11px]">
                <thead className="sticky top-0 z-10">
                  <tr className="border-b border-slate-800 bg-slate-900 text-left text-[9px] uppercase tracking-[0.2em] text-slate-500">
                    <th className="w-1.5 px-1"><span className="sr-only">flag</span></th>
                    <th className="px-4 py-2.5">Time</th>
                    <th className="px-4 py-2.5">Source</th>
                    <th className="px-4 py-2.5">Destination</th>
                    <th className="px-4 py-2.5 text-center">Port</th>
                    <th className="px-4 py-2.5">Flags</th>
                    <th className="px-4 py-2.5 text-right">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <AnimatePresence initial={false}>
                    {feedRows
                      .slice()
                      .reverse()
                      .map((row) => (
                        <TelemetryRow key={row.uid} row={row} />
                      ))}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
            )}
          </Panel>
        </section>
      </main>
      {/* ═══════════ FOOTER ═══════════ */}
      <footer className="relative z-10 w-full overflow-hidden border-t border-slate-800/70 px-5 py-3">
        <div className="mx-auto flex max-w-[1700px] flex-nowrap items-center justify-between gap-6 whitespace-nowrap font-mono text-xs text-slate-600">
          <span className="inline-flex items-center gap-1.5">
            <Cpu className="h-3 w-3 text-purple-400/70" />
            WORLD-MODEL INFERENCE ENGINE — LOCAL · DETERMINISTIC · NO CLOUD ROUND-TRIP
          </span>
          <span className="inline-flex items-center gap-1.5">
            <Network className="h-3 w-3 text-cyan-400/70" />
            CII SOC PROTOTYPE · SMART INDIA HACKATHON
          </span>
        </div>
      </footer>

      {/* ═══════════ ACTIVE ALERT OVERLAY (5s → flash → auto-dismiss) ═══════════ */}
      <AnimatePresence>
        {(alertPhase === "visible" || alertPhase === "flash") && (
          <motion.div
            key="active-alert"
            initial={{ opacity: 0, y: 40, scale: 0.94 }}
            animate={alertMotion.animate}
            transition={alertMotion.transition}
            className="fixed bottom-4 right-4 z-50 w-[368px] max-w-[94vw] overflow-hidden rounded-xl border border-rose-500/50 bg-slate-950/95 shadow-[0_0_60px_rgba(255,61,0,0.35)] backdrop-blur-xl"
          >
            {/* 5s visibility countdown */}
            <div className="h-0.5 w-full bg-slate-800">
              <motion.div
                className="h-full bg-gradient-to-r from-rose-500 to-amber-400"
                initial={{ width: "100%" }}
                animate={{ width: "0%" }}
                transition={{ duration: ALERT_VISIBLE_MS / 1000, ease: "linear" }}
              />
            </div>
            {/* alert header */}
            <div className="flex items-center justify-between border-b border-rose-500/30 bg-rose-500/10 px-4 py-2.5">
              <div className="flex items-center gap-2">
                <Siren className="h-4 w-4 animate-pulse text-rose-500" />
                <span className="text-xs font-bold tracking-widest text-rose-400">ACTIVE ALERT</span>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded border border-rose-500/60 bg-rose-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-rose-300">
                <Skull className="h-3 w-3" /> {ALERT_PAYLOAD.severity}
              </span>
            </div>

            {/* alert body */}
            <div className="space-y-3 px-4 py-4">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Predicted Attack</div>
                <div className="font-mono text-sm font-bold text-slate-50">High-Velocity SSH Brute Force</div>
              </div>
              <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
                <div className="rounded-md border border-slate-800 bg-slate-900/80 px-2.5 py-2">
                  <div className="text-slate-400">ATT&CK STAGE</div>
                  <div className="mt-0.5 font-mono font-bold text-purple-300">{ALERT_PAYLOAD.stage}</div>
                </div>
                <div className="rounded-md border border-slate-800 bg-slate-900/80 px-2.5 py-2">
                  <div className="text-slate-400">TARGET NODE</div>
                  <div className="mt-0.5 font-mono font-bold text-rose-400">{ALERT_PAYLOAD.target}</div>
                </div>
              </div>
              <p className="rounded-md border-l-2 border-rose-500 bg-slate-900/60 px-3 py-2 text-[11px] leading-relaxed text-slate-300">
                {ALERT_PAYLOAD.desc}
              </p>
              <div className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-900/60 px-2.5 py-2 font-mono text-[10px] text-slate-500">
                <span>P(INFILT.) {latest.world_model.toFixed(2)} / THRESHOLD {THRESHOLD.toFixed(2)}</span>
                <span className="font-bold text-amber-400">Δt {latest.time}</span>
              </div>

              {/* isolate action */}
              {isolated ? (
                <div className="flex items-center justify-center gap-2 rounded-md border border-emerald-400/40 bg-emerald-500/10 py-2.5 font-mono text-[11px] font-bold text-emerald-300">
                  <ShieldCheck className="h-4 w-4" /> TARGET NODE {ALERT_PAYLOAD.target} ISOLATED
                </div>
              ) : (
                <button
                  onClick={handleIsolate}
                  className="group flex w-full items-center justify-center gap-2 rounded-md bg-rose-600/90 px-4 py-2.5 text-[11px] font-bold tracking-[0.18em] text-white shadow-[0_0_24px_rgba(255,61,0,0.4)] transition-all hover:bg-rose-500 hover:shadow-[0_0_36px_rgba(255,61,0,0.6)] active:scale-[0.98]"
                >
                  <Terminal className="h-4 w-4 transition-transform group-hover:-rotate-12" />
                  [ ISOLATE TARGET NODE ]
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}