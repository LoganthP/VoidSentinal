import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import "./index.css";
import { AuthProvider, useAuth } from "./lib/auth";
import { ScopeProvider } from "./lib/scope";
import Access from "./pages/Access";
import Alerts from "./pages/Alerts";
import ImportDataset from "./pages/ImportDataset";
import Login from "./pages/Login";
import Models from "./pages/Models";
import Overview from "./pages/Overview";
import SessionDetail from "./pages/SessionDetail";
import Sessions from "./pages/Sessions";
import Sensors from "./pages/Sensors";

function Gate() {
  const { user, checking } = useAuth();
  if (checking) return <div className="grid min-h-screen place-items-center text-sm text-ink-soft">Loading…</div>;
  if (!user) return <Login />;
  return (
    <ScopeProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="sessions/:id" element={<SessionDetail />} />
          <Route path="ml" element={<Models />} />
          <Route path="sensors" element={<Sensors />} />
          <Route path="import" element={<ImportDataset />} />
          <Route path="access" element={<Access />} />
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
