import { Check, KeyRound, LogIn, ShieldCheck, UserPlus, UserRound } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { useAuth, type Role } from "../lib/auth";

interface Options { signup_enabled: boolean; admin_code_configured: boolean }

const ROLE_INFO: Record<Role, { title: string; can: string[] }> = {
  analyst: {
    title: "Analyst",
    can: ["View dashboards, alerts and SSH sessions", "Investigate evidence and record verdicts", "Analyze imported datasets"],
  },
  admin: {
    title: "Admin",
    can: ["Everything an analyst can do", "Import and delete datasets, retrain models", "Manage people and approve admin requests"],
  },
};

function strength(pw: string): { label: string; tone: string; ok: boolean } {
  let score = 0;
  if (pw.length >= 10) score++;
  if (pw.length >= 14) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (pw.length < 10) return { label: "At least 10 characters", tone: "#D1366B", ok: false };
  return score >= 4 ? { label: "Strong", tone: "#1F9E8F", ok: true } : score >= 3 ? { label: "Good", tone: "#B37E05", ok: true }
    : { label: "Weak but allowed; add length or symbols", tone: "#D2560F", ok: true };
}

export default function Login() {
  const { signIn, signUp, expired } = useAuth();
  const [params, setParams] = useSearchParams();
  const [opts, setOpts] = useState<Options | null>(null);
  const mode: "signin" | "signup" = params.get("mode") === "signup" && opts?.signup_enabled !== false ? "signup" : "signin";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api<Options>("/auth/options").then(setOpts).catch(() => setOpts({ signup_enabled: false, admin_code_configured: false })); }, []);

  const switchMode = (m: "signin" | "signup") => {
    const next = new URLSearchParams(params);
    if (m === "signup") next.set("mode", "signup"); else next.delete("mode");
    setParams(next, { replace: true });
    setErr(null); setPassword(""); setConfirm("");
  };

  const pw = strength(password);
  const nameOk = /^[A-Za-z0-9._-]{3,64}$/.test(username.trim());
  const canSignUp = nameOk && pw.ok && password === confirm && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      if (mode === "signin") await signIn(username.trim(), password);
      else await signUp(username.trim(), password, role, role === "admin" ? code.trim() : undefined);
    } catch (ex) { setErr((ex as Error).message); setPassword(""); setConfirm(""); }
    setBusy(false);
  }

  return (
    <div className="grid min-h-screen place-items-center p-4">
      <form onSubmit={submit} className="glass-strong w-full max-w-md p-7" aria-labelledby="auth-title">
        <Link to="/" aria-label="VoidSentinel home" className="mb-4 inline-block">
          <svg viewBox="0 0 40 40" className="h-11 w-11" aria-hidden>
            <circle cx="20" cy="20" r="18" fill="none" stroke="#2F6BFF" strokeOpacity=".18" strokeWidth="2" />
            <circle cx="20" cy="20" r="11" fill="none" stroke="#2F6BFF" strokeOpacity=".35" strokeWidth="2" />
            <circle cx="20" cy="20" r="4.5" fill="#2F6BFF" />
            <path d="M20 20 L35 11" stroke="#2F6BFF" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </Link>
        <h1 id="auth-title" className="h-title text-[1.45rem]">{mode === "signin" ? "Sign in to VoidSentinel" : "Create your VoidSentinel account"}</h1>
        <p className="mt-1 text-sm text-ink-soft">{mode === "signin" ? "Use an existing account to open the SSH decoy dashboard." : "Choose a username, a password and the access you need."}</p>

        {opts?.signup_enabled && (
          <div className="mt-5 grid grid-cols-2 gap-1 rounded-2xl bg-[#EAF1FA] p-1" role="tablist" aria-label="Account">
            {(["signin", "signup"] as const).map((m) => (
              <button key={m} type="button" role="tab" aria-selected={mode === m} onClick={() => switchMode(m)}
                className={`flex items-center justify-center gap-2 rounded-xl py-2 text-sm font-semibold transition ${mode === m ? "bg-white text-ink shadow-glass" : "text-ink-soft hover:text-ink"}`}>
                {m === "signin" ? <><LogIn className="h-4 w-4" />Sign in</> : <><UserPlus className="h-4 w-4" />Create account</>}
              </button>
            ))}
          </div>
        )}

        {expired && mode === "signin" && <p className="mt-3 rounded-xl bg-[#FFF6E0] p-2.5 text-sm">Your session ended. Sign in again to continue.</p>}

        <label className="mt-5 block text-sm">
          <span className="mb-1 block font-medium">Username</span>
          <input className="field w-full" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={64} />
          {mode === "signup" && username && !nameOk && <span className="mt-1 block text-xs text-sev-critical">3–64 characters: letters, numbers, dot, dash or underscore.</span>}
        </label>
        <label className="mt-3 block text-sm">
          <span className="mb-1 block font-medium">Password</span>
          <input className="field w-full" type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} required />
          {mode === "signup" && password && <span className="mt-1 block text-xs font-medium" style={{ color: pw.tone }}>{pw.label}</span>}
        </label>

        {mode === "signup" && (
          <>
            <label className="mt-3 block text-sm">
              <span className="mb-1 block font-medium">Confirm password</span>
              <input className="field w-full" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
              {confirm && confirm !== password && <span className="mt-1 block text-xs text-sev-critical">Passwords don't match.</span>}
            </label>

            <fieldset className="mt-4">
              <legend className="mb-1.5 text-sm font-medium">Role</legend>
              <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="Role">
                {(["analyst", "admin"] as Role[]).map((r) => (
                  <button key={r} type="button" role="radio" aria-checked={role === r} data-on={role === r} onClick={() => setRole(r)}
                    className={`soft-btn flex-col items-start gap-1 p-3 text-left ${role === r ? "ring-2 ring-signal/40" : ""}`}>
                    <span className="flex items-center gap-1.5 text-sm font-semibold text-ink">
                      {r === "admin" ? <ShieldCheck className="h-4 w-4 text-signal" /> : <UserRound className="h-4 w-4 text-signal" />}{ROLE_INFO[r].title}
                    </span>
                    <ul className="space-y-0.5 text-[0.72rem] font-normal text-ink-soft">
                      {ROLE_INFO[r].can.map((c) => <li key={c} className="flex gap-1"><Check className="mt-0.5 h-3 w-3 shrink-0 text-sev-low" />{c}</li>)}
                    </ul>
                  </button>
                ))}
              </div>
            </fieldset>

            {role === "admin" && (
              <div className="mt-3 rounded-2xl bg-white/70 p-3 text-sm">
                {opts?.admin_code_configured ? (
                  <label className="block">
                    <span className="mb-1 flex items-center gap-1.5 font-medium"><KeyRound className="h-4 w-4 text-signal" />Admin invite code</span>
                    <input className="field w-full" type="password" autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} placeholder="From your project lead (optional)" />
                    <span className="mt-1 block text-xs text-ink-soft">With a valid code you become an admin now. Without one, you get analyst access and an existing admin approves your admin request.</span>
                  </label>
                ) : (
                  <p className="text-xs text-ink-soft">You'll get analyst access now, and an existing admin can approve your admin request on the Access page.</p>
                )}
              </div>
            )}
          </>
        )}

        {err && <p role="alert" className="mt-3 text-sm text-sev-critical">{err}</p>}
        <button className="btn-primary mt-5 w-full" disabled={mode === "signin" ? busy || !username || !password : !canSignUp}>
          {mode === "signin"
            ? <><LogIn className="h-4 w-4" />{busy ? "Signing in…" : "Sign in"}</>
            : <><UserPlus className="h-4 w-4" />{busy ? "Creating account…" : role === "admin" && (!code || !opts?.admin_code_configured) ? "Create account and request admin" : "Create account"}</>}
        </button>
        <p className="mt-4 text-xs text-ink-faint">
          {mode === "signin"
            ? opts?.signup_enabled ? <>New here? <button type="button" className="font-semibold text-signal" onClick={() => switchMode("signup")}>Create an account</button>.</> : "Ask an admin to create your account."
            : <>Already have an account? <button type="button" className="font-semibold text-signal" onClick={() => switchMode("signin")}>Sign in</button>. Passwords are stored hashed.</>}
        </p>
      </form>
    </div>
  );
}
