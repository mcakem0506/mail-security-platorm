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
import { GatewaysPage } from "./pages/GatewaysPage";
import { ReportsPage } from "./pages/ReportsPage";
import { QueuePage } from "./pages/QueuePage";
import { DetectionQualityPage } from "./pages/DetectionQualityPage";
import { SimulatorPage } from "./pages/SimulatorPage";
import { ReleasesPage } from "./pages/ReleasesPage";
import { RealFlowPage } from "./pages/RealFlowPage";
import { ReevaluationPage } from "./pages/ReevaluationPage";

interface NavItem {
  to: string;
  label: string;
  permission?: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

/**
 * Navigation grouped by what an analyst is doing (ТЗ 1.0.3B §45).
 *
 * Investigation and detection operations are different jobs, often different people, and a flat
 * list of fourteen links made them look like one. The employee-facing surfaces are not here at
 * all: internal detection operations are not something a reporting employee should see.
 */
const NAV_GROUPS: NavGroup[] = [
  {
    title: "Расследования",
    items: [
      { to: "/", label: "Обзор", permission: "view:investigations" },
      { to: "/queue", label: "Очередь", permission: "view:incidents" },
      { to: "/incidents", label: "Инциденты", permission: "view:incidents" },
      { to: "/investigations", label: "Письма", permission: "view:investigations" },
      { to: "/campaigns", label: "Кампании", permission: "view:campaigns" },
    ],
  },
  {
    title: "Детектирование",
    items: [
      { to: "/detection", label: "Качество", permission: "quality:read" },
      { to: "/simulator", label: "Симулятор", permission: "detection:simulate" },
      { to: "/releases", label: "Выпуски", permission: "quality:read" },
      { to: "/reevaluation", label: "Переоценка", permission: "quality:read" },
      { to: "/real-flow", label: "Реальный поток", permission: "realflow:read" },
    ],
  },
  {
    title: "Threat Intelligence",
    items: [{ to: "/threat-intel", label: "Индикаторы", permission: "search:indicators" }],
  },
  {
    title: "Администрирование",
    items: [
      { to: "/reports", label: "Отчёты", permission: "view:investigations" },
      { to: "/remediation", label: "Реагирование", permission: "view:incidents" },
      { to: "/gateways", label: "Почтовые шлюзы", permission: "view:investigations" },
      { to: "/admin", label: "Настройки", permission: "view:audit" },
    ],
  },
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
  // A group with nothing the viewer may open is not rendered at all: an empty heading tells
  // someone a section exists and that they cannot have it, which helps nobody.
  const visible = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => can(item.permission)),
  })).filter((group) => group.items.length > 0);

  return (
    <BrowserRouter>
      <div className="layout">
        <aside className="sidebar">
          <div className="brand">Mail Security</div>
          <nav>
            {visible.map((group) => (
              <div key={group.title} className="nav-group">
                <div className="nav-group__title">{group.title}</div>
                {group.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === "/"}
                    className={({ isActive }) =>
                      isActive ? "nav-link nav-link--active" : "nav-link"
                    }
                  >
                    {item.label}
                  </NavLink>
                ))}
              </div>
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
            <Route path="/queue" element={<QueuePage user={user} />} />
            <Route path="/investigations" element={<InvestigationsPage />} />
            <Route path="/messages/:messageId" element={<MessagePage />} />
            <Route path="/incidents" element={<IncidentsPage user={user} />} />
            <Route path="/campaigns" element={<CampaignsPage />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/detection" element={<DetectionQualityPage user={user} />} />
            <Route path="/simulator" element={<SimulatorPage />} />
            <Route path="/releases" element={<ReleasesPage user={user} />} />
            <Route path="/reevaluation" element={<ReevaluationPage user={user} />} />
            <Route path="/real-flow" element={<RealFlowPage user={user} />} />
            <Route path="/reports" element={<ReportsPage user={user} />} />
            <Route path="/remediation" element={<RemediationPage user={user} />} />
            <Route path="/gateways" element={<GatewaysPage user={user} />} />
            <Route path="/admin" element={<AdminPage user={user} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
