import { LogIn } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useAuth } from "../lib/auth";

export default function Login() {
  const { signIn, expired } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try { await signIn(username.trim(), password); }
    catch (ex) { setErr((ex as Error).message); setPassword(""); }
    setBusy(false);
  }

  return (
    <div className="grid min-h-screen place-items-center p-4">
      <form onSubmit={submit} className="glass-strong w-full max-w-sm p-7" aria-labelledby="signin-title">
        <svg viewBox="0 0 40 40" className="mb-4 h-11 w-11" aria-hidden>
          <circle cx="20" cy="20" r="18" fill="none" stroke="#2F6BFF" strokeOpacity=".18" strokeWidth="2" />
          <circle cx="20" cy="20" r="11" fill="none" stroke="#2F6BFF" strokeOpacity=".35" strokeWidth="2" />
          <circle cx="20" cy="20" r="4.5" fill="#2F6BFF" />
          <path d="M20 20 L35 11" stroke="#2F6BFF" strokeWidth="2" strokeLinecap="round" />
        </svg>
        <h1 id="signin-title" className="h-title text-[1.45rem]">Sign in to VoidSentinel</h1>
        <p className="mt-1 text-sm text-ink-soft">Analyst access to the SSH decoy dashboard.</p>
        {expired && <p className="mt-3 rounded-xl bg-[#FFF6E0] p-2.5 text-sm">Your session ended. Sign in again to continue.</p>}
        <label className="mt-5 block text-sm">
          <span className="mb-1 block font-medium">Username</span>
          <input className="field w-full" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label className="mt-3 block text-sm">
          <span className="mb-1 block font-medium">Password</span>
          <input className="field w-full" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {err && <p role="alert" className="mt-3 text-sm text-sev-critical">{err}</p>}
        <button className="btn-primary mt-5 w-full" disabled={busy || !username || !password}>
          <LogIn className="h-4 w-4" />{busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="mt-4 text-xs text-ink-faint">Accounts are created from VS_ADMIN_* and VS_ANALYST_* in .env on first start. Admins manage access afterwards.</p>
      </form>
    </div>
  );
}
