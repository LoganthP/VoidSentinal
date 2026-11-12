import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "./api";

export interface User { id: number; username: string; role: "analyst" | "admin" }

interface Ctx {
  user: User | null;
  checking: boolean;
  isAdmin: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  expired: boolean;
}

const AuthCtx = createContext<Ctx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    api<User | null>("/auth/me").then((u) => setUser(u)).catch(() => setUser(null)).finally(() => setChecking(false));
    const onOut = () => { setUser((u) => { if (u) setExpired(true); return null; }); };
    window.addEventListener("vs-signed-out", onOut);
    return () => window.removeEventListener("vs-signed-out", onOut);
  }, []);

  const signIn = useCallback(async (username: string, password: string) => {
    const u = await api<User>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    setExpired(false);
    setUser(u);
  }, []);

  const signOut = useCallback(async () => {
    try { await api("/auth/logout", { method: "POST" }); } catch { /* already signed out */ }
    setExpired(false);
    setUser(null);
  }, []);

  return (
    <AuthCtx.Provider value={{ user, checking, isAdmin: user?.role === "admin", signIn, signOut, expired }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth() {
  const c = useContext(AuthCtx);
  if (!c) throw new Error("useAuth must be used inside AuthProvider");
  return c;
}
