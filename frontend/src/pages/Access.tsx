import { UserPlus } from "lucide-react";
import { useState } from "react";
import { Card, ErrorBanner, PageHeader } from "../components/ui";
import { api, usePoll } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtTime } from "../lib/format";

interface U { id: number; username: string; role: "analyst" | "admin"; active: number; created_at: number; last_login: number | null; sessions: number; requested_role: "admin" | null; created_via: string | null }

export default function Access() {
  const { user, isAdmin } = useAuth();
  const { data, error, reload } = usePoll<{ items: U[] }>(isAdmin ? "/users" : null);
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const pending = data?.items.filter((u) => u.requested_role === "admin" && u.active) ?? [];
  if (!isAdmin) return <><PageHeader title="Access" /><ErrorBanner message="Only admins can manage access." /></>;

  async function run(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setMsg(null);
    try { await fn(); setMsg(ok); reload(); } catch (e) { setErr((e as Error).message); }
  }

  return (
    <>
      <PageHeader title="Access" subtitle="Analysts can view telemetry, investigate alerts and record verdicts. Admins can also import datasets, retrain models and manage access. Changing a role, password or status signs that person out immediately." />
      {(error || err) && <div className="mb-4"><ErrorBanner message={(error || err)!} /></div>}
      {msg && <p className="mb-4 text-sm font-medium text-sev-low">{msg}</p>}
      {pending.length > 0 && (
        <Card title={`Admin requests (${pending.length})`} className="mb-4 ring-2 ring-sev-medium/25">
          <ul className="flex flex-col gap-2">
            {pending.map((u) => (
              <li key={u.id} className="flex flex-wrap items-center gap-3 rounded-2xl bg-white/70 p-3 text-sm">
                <span className="min-w-0 flex-1"><b className="font-semibold">{u.username}</b> created an account on {fmtTime(u.created_at)} and asked for admin access. They currently have analyst access.</span>
                <button className="btn-primary py-1.5" onClick={() => run(() => api(`/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ role: "admin" }) }), `${u.username} is now an admin`)}>Approve</button>
                <button className="btn-ghost py-1.5" onClick={() => run(() => api(`/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ decline_request: true }) }), `Declined ${u.username}'s request; they stay an analyst`)}>Decline</button>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 xl:col-span-8">
          <Card title="People">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead><tr className="text-left text-xs text-ink-faint"><th className="py-2 font-medium">Username</th><th className="font-medium">Role</th><th className="font-medium">Status</th><th className="font-medium">Last sign-in</th><th className="font-medium">Actions</th></tr></thead>
                <tbody>
                  {data?.items.map((u) => (
                    <tr key={u.id} className="border-t border-ink/5">
                      <td className="py-2.5 font-medium">{u.username}{u.id === user?.id && <span className="ml-2 text-xs text-ink-faint">(you)</span>}
                        {u.created_via === "signup" && <span className="ml-2 rounded-md bg-signal-soft px-1.5 text-[0.68rem] font-semibold text-signal">self sign-up</span>}
                        {u.requested_role === "admin" && <span className="ml-2 rounded-md bg-[#FFF6E0] px-1.5 text-[0.68rem] font-semibold text-sev-medium">admin requested</span>}
                      </td>
                      <td>
                        <select className="field py-1 text-sm" value={u.role} disabled={u.id === user?.id}
                                onChange={(e) => run(() => api(`/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ role: e.target.value }) }), `${u.username} is now ${e.target.value}`)}>
                          <option value="analyst">Analyst</option><option value="admin">Admin</option>
                        </select>
                      </td>
                      <td>{u.active ? <span className="text-sev-low">Active</span> : <span className="text-sev-critical">Disabled</span>}</td>
                      <td className="text-ink-soft">{u.last_login ? fmtTime(u.last_login) : "Never"}</td>
                      <td className="space-x-3 whitespace-nowrap">
                        {u.id !== user?.id && (
                          <button className="text-xs font-semibold text-signal" onClick={() => run(() => api(`/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ active: !u.active }) }), u.active ? `${u.username} disabled` : `${u.username} enabled`)}>
                            {u.active ? "Disable" : "Enable"}
                          </button>
                        )}
                        <button className="text-xs font-semibold text-signal" onClick={() => {
                          const pw = window.prompt(`New password for ${u.username} (at least 10 characters)`);
                          if (pw) run(() => api(`/users/${u.id}`, { method: "PATCH", body: JSON.stringify({ password: pw }) }), `Password changed for ${u.username}`);
                        }}>Reset password</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
        <div className="col-span-12 xl:col-span-4">
          <Card title="Add a person">
            <div className="flex flex-col gap-3 text-sm">
              <label><span className="mb-1 block text-xs text-ink-faint">Username</span><input className="field w-full" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
              <label><span className="mb-1 block text-xs text-ink-faint">Temporary password (10+ characters)</span><input type="password" autoComplete="new-password" className="field w-full" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
              <label><span className="mb-1 block text-xs text-ink-faint">Role</span>
                <select className="field w-full" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="analyst">Analyst</option><option value="admin">Admin</option></select>
              </label>
              <button className="btn-primary" disabled={form.username.length < 3 || form.password.length < 10}
                      onClick={() => run(async () => { await api("/users", { method: "POST", body: JSON.stringify(form) }); setForm({ username: "", password: "", role: "analyst" }); }, `Added ${form.username}`)}>
                <UserPlus className="h-4 w-4" />Add person
              </button>
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
