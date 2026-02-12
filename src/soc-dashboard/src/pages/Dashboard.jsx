import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
    AlertTriangle, ShieldAlert, Activity, Clock, TrendingUp,
    TrendingDown, Zap, Users, FileSearch, Loader2
} from 'lucide-react';
import {
    AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
    XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { api } from '../api';

// Fallback mock data (shown when backend is unavailable)
const defaultStats = {
    total: 0, newAlerts: 0, inProgress: 0, escalated: 0, resolved: 0, closed: 0,
    critical: 0, high: 0, medium: 0, low: 0, slaBreaches: 0, unassignedCritical: 0,
};

const trendData = [
    { time: '00:00', alerts: 4, incidents: 1 }, { time: '02:00', alerts: 2, incidents: 0 },
    { time: '04:00', alerts: 1, incidents: 0 }, { time: '06:00', alerts: 3, incidents: 1 },
    { time: '08:00', alerts: 8, incidents: 2 }, { time: '10:00', alerts: 15, incidents: 3 },
    { time: '12:00', alerts: 12, incidents: 2 }, { time: '14:00', alerts: 18, incidents: 4 },
    { time: '16:00', alerts: 22, incidents: 5 }, { time: '18:00', alerts: 14, incidents: 3 },
    { time: '20:00', alerts: 8, incidents: 1 }, { time: '22:00', alerts: 5, incidents: 1 },
];

const container = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const item = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { duration: 0.35 } },
};

function AnimatedCounter({ value, duration = 1.5 }) {
    const [count, setCount] = useState(0);
    useEffect(() => {
        let start = 0;
        const step = Math.max(1, Math.ceil(value / (duration * 60)));
        const timer = setInterval(() => {
            start += step;
            if (start >= value) { setCount(value); clearInterval(timer); }
            else setCount(start);
        }, 1000 / 60);
        return () => clearInterval(timer);
    }, [value, duration]);
    return <span className="stat-value">{count}</span>;
}

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{
            background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
            borderRadius: 8, padding: '10px 14px', fontSize: '0.8rem',
        }}>
            <p style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>{label}</p>
            {payload.map((p, i) => (
                <p key={i} style={{ color: p.color }}>{p.name}: <strong>{p.value}</strong></p>
            ))}
        </div>
    );
};

export default function Dashboard() {
    const navigate = useNavigate();
    const [stats, setStats] = useState(defaultStats);
    const [recentAlerts, setRecentAlerts] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const loadData = async () => {
            setLoading(true);
            try {
                const [statsRes, alertsRes] = await Promise.all([
                    api.getAlertStats(),
                    api.getAlerts({ pageSize: 5, sortBy: 'CreatedAt', sortOrder: 'desc' }),
                ]);

                if (statsRes?.success && statsRes?.data) {
                    const d = statsRes.data;
                    setStats({
                        total: (d.byStatus?.New || 0) + (d.byStatus?.InProgress || 0) + (d.byStatus?.Escalated || 0) +
                            (d.byStatus?.Resolved || 0) + (d.byStatus?.Closed || 0),
                        newAlerts: d.byStatus?.New || 0,
                        inProgress: d.byStatus?.InProgress || 0,
                        escalated: d.byStatus?.Escalated || 0,
                        resolved: d.byStatus?.Resolved || 0,
                        closed: d.byStatus?.Closed || 0,
                        critical: d.bySeverity?.Critical || 0,
                        high: d.bySeverity?.High || 0,
                        medium: d.bySeverity?.Medium || 0,
                        low: d.bySeverity?.Low || 0,
                        slaBreaches: d.slaBreaches || 0,
                        unassignedCritical: d.unassignedCritical || 0,
                    });
                }

                if (alertsRes?.success && alertsRes?.data) {
                    const items = Array.isArray(alertsRes.data) ? alertsRes.data : (alertsRes.data.items || []);
                    setRecentAlerts(items.slice(0, 5).map(a => ({
                        id: a.id,
                        title: a.title,
                        severity: a.severity,
                        status: a.status,
                        time: a.createdAt ? new Date(a.createdAt).toLocaleString() : '',
                        source: a.sourceIP || a.affectedUser || '',
                    })));
                }
            } catch (err) {
                console.error('Dashboard load error:', err);
            }
            setLoading(false);
        };
        loadData();
    }, []);

    const severityData = [
        { name: 'Critical', value: stats.critical, color: '#ef4444' },
        { name: 'High', value: stats.high, color: '#f59e0b' },
        { name: 'Medium', value: stats.medium, color: '#06b6d4' },
        { name: 'Low', value: stats.low, color: '#10b981' },
    ].filter(d => d.value > 0);

    const statusData = [
        { name: 'New', count: stats.newAlerts },
        { name: 'InProgress', count: stats.inProgress },
        { name: 'Escalated', count: stats.escalated },
        { name: 'Resolved', count: stats.resolved },
        { name: 'Closed', count: stats.closed },
    ];

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            {/* Page Header */}
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Security Operations Center</h2>
                    <p>Real-time threat monitoring and incident response</p>
                </div>
                <div className="flex gap-sm">
                    <button className="btn btn-ghost btn-sm" onClick={() => navigate('/alerts')}>
                        <AlertTriangle size={14} /> View All Alerts
                    </button>
                </div>
            </motion.div>

            {loading && (
                <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>
                    <Loader2 size={22} className="spin" style={{ color: 'var(--cyan-400)' }} />
                    <p style={{ marginTop: 8 }}>Loading dashboard data...</p>
                </div>
            )}

            {/* ── Stat Cards ── */}
            <motion.div variants={item} className="stat-grid">
                <div className="stat-card critical">
                    <div className="stat-icon"><ShieldAlert size={22} /></div>
                    <AnimatedCounter value={stats.critical} />
                    <div className="stat-label">Critical Alerts</div>
                </div>
                <div className="stat-card high">
                    <div className="stat-icon"><AlertTriangle size={22} /></div>
                    <AnimatedCounter value={stats.high} />
                    <div className="stat-label">High Severity</div>
                </div>
                <div className="stat-card medium">
                    <div className="stat-icon"><Activity size={22} /></div>
                    <AnimatedCounter value={stats.total} />
                    <div className="stat-label">Total Alerts</div>
                </div>
                <div className="stat-card low">
                    <div className="stat-icon"><Clock size={22} /></div>
                    <AnimatedCounter value={stats.slaBreaches} />
                    <div className="stat-label">SLA Breaches</div>
                </div>
                <div className="stat-card info">
                    <div className="stat-icon"><Zap size={22} /></div>
                    <AnimatedCounter value={stats.inProgress} />
                    <div className="stat-label">In Progress</div>
                </div>
            </motion.div>

            {/* ── Charts Row ── */}
            <motion.div variants={item} className="chart-grid">
                <div className="chart-card">
                    <h3>Alert Trend (24h)</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <AreaChart data={trendData}>
                            <defs>
                                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="incidentGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Area type="monotone" dataKey="alerts" stroke="#06b6d4" fill="url(#alertGrad)" strokeWidth={2} name="Alerts" />
                            <Area type="monotone" dataKey="incidents" stroke="#ef4444" fill="url(#incidentGrad)" strokeWidth={2} name="Incidents" />
                            <Legend wrapperStyle={{ fontSize: 12, color: 'var(--text-muted)' }} />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                <div className="chart-card">
                    <h3>Severity Distribution</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                            <Pie data={severityData.length > 0 ? severityData : [{ name: 'None', value: 1, color: '#374151' }]}
                                cx="50%" cy="50%" innerRadius={60} outerRadius={95}
                                paddingAngle={4} dataKey="value" stroke="none">
                                {(severityData.length > 0 ? severityData : [{ color: '#374151' }]).map((entry, idx) => (
                                    <Cell key={idx} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip content={<CustomTooltip />} />
                            <Legend wrapperStyle={{ fontSize: 12, color: 'var(--text-muted)' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </motion.div>

            <motion.div variants={item} className="chart-grid">
                <div className="chart-card">
                    <h3>Alert Status Breakdown</h3>
                    <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={statusData} barSize={28}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} name="Alerts" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                {/* Recent Alerts Table */}
                <div className="chart-card">
                    <h3>Recent Alerts</h3>
                    {recentAlerts.length > 0 ? (
                        <table className="data-table">
                            <thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th>Time</th></tr></thead>
                            <tbody>
                                {recentAlerts.map((a, i) => (
                                    <motion.tr key={a.id || i}
                                        initial={{ opacity: 0, x: -10 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: 0.8 + i * 0.08 }}
                                        onClick={() => navigate('/alerts')}
                                        style={{ cursor: 'pointer' }}
                                    >
                                        <td>
                                            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.82rem' }}>{a.title}</div>
                                            {a.source && <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2 }}>{a.source}</div>}
                                        </td>
                                        <td><span className={`severity-badge ${(a.severity || '').toLowerCase()}`}>{a.severity}</span></td>
                                        <td><span className={`status-badge ${(a.status || '').toLowerCase()}`}>{a.status}</span></td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>{a.time}</td>
                                    </motion.tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)' }}>
                            No alerts to display. Start the API server to see live data.
                        </div>
                    )}
                </div>
            </motion.div>
        </motion.div>
    );
}
