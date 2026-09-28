import { useCallback, useEffect, useState } from "react";
import { BrowserRouter, Navigate, NavLink, Route, Routes } from "react-router-dom";
import { ApiError, api, type CurrentUser } from "./api/client";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { MessagePage } from "./pages/MessagePage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { CampaignsPage } from "./pages/CampaignsPage";
import { RemediationPage } from "./pages/RemediationPage";
import { AdminPage } from "./pages/AdminPage";
import { ThreatIntelPage } from "./pages/ThreatIntelPage";
import { ReportsPage } from "./pages/ReportsPage";

interface NavItem {
  to: string;
  label: string;
  permission?: string;
}

const NAV: NavItem[] = [
  { to: "/", label: "Обзор", permission: "view:investigations" },
  { to: "/investigations", label: "Расследования", permission: "view:investigations" },
  { to: "/incidents", label: "Инциденты", permission: "view:incidents" },
  { to: "/campaigns", label: "Кампании", permission: "view:campaigns" },
  { to: "/threat-intel", label: "Threat Intelligence", permission: "search:indicators" },
  { to: "/reports", label: "Отчёты", permission: "view:investigations" },
  { to: "/remediation", label: "Реагирование", permission: "view:incidents" },
  { to: "/admin", label: "Администрирование", permission: "view:audit" },
];

export function App() {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setUser(await api.me());
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) {
        console.error("session check failed", error);
      }
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  }, []);

  if (loading) {
    return <div className="boot">Загрузка…</div>;
  }
  if (!user) {
    return <LoginPage onSuccess={refresh} />;
  }

  const can = (permission?: string) => !permission || user.permissions.includes(permission);
  const visible = NAV.filter((item) => can(item.permission));

  return (
    <BrowserRouter>
      <div className="layout">
        <aside className="sidebar">
          <div className="brand">Mail Security</div>
          <nav>
            {visible.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) => (isActive ? "nav-link nav-link--active" : "nav-link")}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar__footer">
            <div className="user">
              <div className="user__email">{user.email}</div>
              <div className="user__role">{user.role_label}</div>
            </div>
            <button type="button" className="button button--ghost" onClick={() => void logout()}>
              Выйти
            </button>
          </div>
        </aside>
        <main className="content">
          <Routes>
            <Route
              path="/"
              element={can("view:investigations") ? <DashboardPage /> : <Navigate to="/incidents" replace />}
            />
            <Route path="/investigations" element={<InvestigationsPage />} />
            <Route path="/messages/:messageId" element={<MessagePage />} />
            <Route path="/incidents" element={<IncidentsPage user={user} />} />
            <Route path="/campaigns" element={<CampaignsPage />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/reports" element={<ReportsPage user={user} />} />
            <Route path="/remediation" element={<RemediationPage user={user} />} />
            <Route path="/admin" element={<AdminPage user={user} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
