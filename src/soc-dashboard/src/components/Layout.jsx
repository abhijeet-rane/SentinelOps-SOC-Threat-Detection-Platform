import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { setToken } from '../api';
import { stop as stopAlertStream } from '../alertStream';
import {
    Shield, LayoutDashboard, AlertTriangle, FileSearch, BarChart3,
    Settings, BookOpen, Bell, Search, LogOut, Activity, Zap, ScrollText, Database, FileText
} from 'lucide-react';

/* ── Role-based nav config ──
   roles: array of roles that can see this item ('*' = everyone)
*/
const NAV_ITEMS = [
    { section: 'Operations' },
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true, roles: ['*'] },
    { to: '/alerts', label: 'Alerts', icon: AlertTriangle, badge: '!', roles: ['*'] },
    { to: '/incidents', label: 'Incidents', icon: FileSearch, roles: ['*'] },

    { section: 'Intelligence' },
    { to: '/threatintel', label: 'Threat Intel', icon: Database, roles: ['*'] },
    { to: '/analytics', label: 'Analytics', icon: BarChart3, roles: ['Admin', 'SOC Manager', 'Analyst'] },
    { to: '/mitre', label: 'MITRE ATT&CK', icon: Activity, roles: ['Admin', 'SOC Manager', 'Analyst'] },

    { section: 'Management' },
    { to: '/playbooks', label: 'Playbooks', icon: Zap, roles: ['Admin', 'SOC Manager'] },
    { to: '/reports', label: 'Reports', icon: FileText, roles: ['Admin', 'SOC Manager'] },
    { to: '/settings', label: 'Settings', icon: Settings, roles: ['Admin'] },
    { to: '/audit', label: 'Audit Log', icon: ScrollText, roles: ['Admin', 'SOC Manager'] },
];

export default function Layout() {
    const navigate = useNavigate();
    const user = JSON.parse(localStorage.getItem('soc_user') || '{}');
    const userRole = user.role || '';

    const canSee = (item) => {
        if (!item.roles) return true;
        if (item.roles.includes('*')) return true;
        return item.roles.includes(userRole);
    };

    const handleLogout = async () => {
        await stopAlertStream();                 // close the SignalR connection cleanly
        setToken(null);
        localStorage.removeItem('soc_user');
        navigate('/login');
    };

    return (
        <div className="app-layout scanline">
            <div className="cyber-grid-bg" />

            {/* ── Sidebar ── */}
            <aside className="sidebar">
                <div className="sidebar-logo">
                    <div className="logo-icon"><Shield size={22} color="#fff" /></div>
                    <div>
                        <h1>SENTINEL</h1>
                        <div className="logo-sub">SOC Platform v2.0</div>
                    </div>
                </div>

                <nav className="sidebar-nav">
                    {NAV_ITEMS.map((item, i) => {
                        if (item.section) return <span key={i} className="sidebar-section">{item.section}</span>;
                        if (!canSee(item)) return null;
                        const Icon = item.icon;
                        return (
                            <NavLink key={item.to} to={item.to} end={item.end}
                                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <Icon size={18} /> {item.label}
                                {item.badge && <span className="badge">{item.badge}</span>}
                            </NavLink>
                        );
                    })}
                </nav>

                <div className="sidebar-footer">
                    <div className="user-card">
                        <div className="user-avatar">{(user.username || 'A')[0].toUpperCase()}</div>
                        <div className="user-info" style={{ flex: 1 }}>
                            <div className="user-name">{user.username || 'Analyst'}</div>
                            <div className="user-role">{userRole || 'SOC Analyst'}</div>
                        </div>
                        <button onClick={handleLogout} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                            <LogOut size={16} />
                        </button>
                    </div>
                </div>
            </aside>

            {/* ── Header ── */}
            <header className="header">
                <div className="header-left">
                    <div className="live-indicator">
                        <span className="live-dot" />
                        System Active
                    </div>
                </div>
                <div className="header-right">
                    <div style={{ position: 'relative' }}>
                        <input type="text" className="form-input" placeholder="Search alerts, incidents..." style={{ width: 260, paddingLeft: 36, fontSize: '0.82rem' }} />
                        <Search size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                    </div>
                    <button className="header-btn">
                        <Bell size={16} />
                        <span className="notif-dot" />
                    </button>
                </div>
            </header>

            {/* ── Main Content ── */}
            <main className="main-content">
                <Outlet />
            </main>
        </div>
    );
}
