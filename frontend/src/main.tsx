import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useSearchParams } from "react-router-dom";
import Layout from "./components/Layout";
import "./index.css";
import { AuthProvider, useAuth } from "./lib/auth";
import { ScopeProvider } from "./lib/scope";
import Access from "./pages/Access";
import Alerts from "./pages/Alerts";
import ImportDataset from "./pages/ImportDataset";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Models from "./pages/Models";
import Overview from "./pages/Overview";
import SessionDetail from "./pages/SessionDetail";
import Sessions from "./pages/Sessions";
import Sensors from "./pages/Sensors";

/** Only same-site paths are allowed as a post-sign-in destination. */
function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/signin") ? next : "/";
}

function ToSignIn() {
  const loc = useLocation();
  return <Navigate to={`/signin?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />;
}

function AfterSignIn() {
  const [params] = useSearchParams();
  return <Navigate to={safeNext(params.get("next"))} replace />;
}

function Gate() {
  const { user, checking } = useAuth();
  if (checking) return <div className="grid min-h-screen place-items-center text-sm text-ink-soft">Loading…</div>;
  if (!user) {
    return (
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/signin" element={<Login />} />
        <Route path="*" element={<ToSignIn />} />
      </Routes>
    );
  }
  return (
    <ScopeProvider>
      <Routes>
        <Route path="/signin" element={<AfterSignIn />} />
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="sessions/:id" element={<SessionDetail />} />
          <Route path="ml" element={<Models />} />
          <Route path="sensors" element={<Sensors />} />
          <Route path="import" element={<ImportDataset />} />
          <Route path="access" element={<Access />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ScopeProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
