import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { setToken } from '../api';
import {
    Shield, LayoutDashboard, AlertTriangle, FileSearch, BarChart3,
    Settings, BookOpen, Bell, Search, LogOut, Activity, Zap, ScrollText, Database
} from 'lucide-react';

export default function Layout() {
    const navigate = useNavigate();
    const user = JSON.parse(localStorage.getItem('soc_user') || '{}');

    const handleLogout = () => {
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
                    <span className="sidebar-section">Operations</span>
                    <NavLink to="/" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <LayoutDashboard size={18} /> Dashboard
                    </NavLink>
                    <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <AlertTriangle size={18} /> Alerts
                        <span className="badge">!</span>
                    </NavLink>
                    <NavLink to="/incidents" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <FileSearch size={18} /> Incidents
                    </NavLink>

                    <span className="sidebar-section">Intelligence</span>
                    <NavLink to="/threatintel" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <Database size={18} /> Threat Intel
                    </NavLink>
                    <NavLink to="/analytics" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <BarChart3 size={18} /> Analytics
                    </NavLink>
                    <NavLink to="/mitre" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <Activity size={18} /> MITRE ATT&CK
                    </NavLink>

                    <span className="sidebar-section">Management</span>
                    <NavLink to="/playbooks" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <Zap size={18} /> Playbooks
                    </NavLink>
                    <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <Settings size={18} /> Settings
                    </NavLink>
                    <NavLink to="/audit" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <ScrollText size={18} /> Audit Log
                    </NavLink>
                </nav>

                <div className="sidebar-footer">
                    <div className="user-card">
                        <div className="user-avatar">{(user.username || 'A')[0].toUpperCase()}</div>
                        <div className="user-info" style={{ flex: 1 }}>
                            <div className="user-name">{user.username || 'Analyst'}</div>
                            <div className="user-role">{user.role || 'SOC Analyst'}</div>
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
