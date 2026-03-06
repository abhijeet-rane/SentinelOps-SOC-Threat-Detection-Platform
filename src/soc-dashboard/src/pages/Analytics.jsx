import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { BarChart3, TrendingUp, Users, Clock, Target, Loader } from 'lucide-react';
import {
    LineChart, Line, AreaChart, Area,
    XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { api } from '../api';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.06 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '10px 14px', fontSize: '0.8rem' }}>
            <p style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>{label}</p>
            {payload.map((p, i) => (
                <p key={i} style={{ color: p.color }}>{p.name}: <strong>{p.value}</strong></p>
            ))}
        </div>
    );
};

export default function Analytics() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const timer = setTimeout(() => {
            (async () => {
                const res = await api.getAnalytics();
                if (res.success) setData(res.data);
                setLoading(false);
            })();
        }, 0);
        return () => clearTimeout(timer);
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center" style={{ height: '60vh' }}>
                <Loader className="spin" size={32} style={{ color: 'var(--cyan-400)' }} />
            </div>
        );
    }

    const kpis = data?.kpis;
    const weeklyTrend = data?.weeklyTrend || [];
    const analysts = data?.analystPerformance || [];

    const kpiCards = [
        { label: 'MTTD', value: kpis?.mttd || 'N/A', desc: 'Mean time to detect', color: 'var(--cyan-400)' },
        { label: 'MTTR', value: kpis?.mttr || 'N/A', desc: 'Mean time to respond', color: 'var(--green-400)' },
        { label: 'MTTC', value: kpis?.mttc || 'N/A', desc: 'Mean time to contain', color: 'var(--amber-400)' },
        { label: 'False +', value: kpis?.falsePositiveRate || '0%', desc: 'False positive rate', color: 'var(--purple-400)' },
    ];

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Security Analytics</h2>
                    <p>Operational KPIs, trends, and analyst performance metrics</p>
                </div>
            </motion.div>

            {/* KPI Cards */}
            <motion.div variants={item} className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
                {kpiCards.map((kpi, i) => (
                    <motion.div key={kpi.label} className="stat-card info"
                        initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.1 }}>
                        <div className="stat-icon" style={{ background: `${kpi.color}15`, color: kpi.color }}>
                            {i === 0 ? <Target size={22} /> : i === 1 ? <Clock size={22} /> : i === 2 ? <BarChart3 size={22} /> : <TrendingUp size={22} />}
                        </div>
                        <div className="stat-value" style={{ color: kpi.color }}>{kpi.value}</div>
                        <div className="stat-label">{kpi.desc}</div>
                    </motion.div>
                ))}
            </motion.div>

            {/* Charts */}
            <motion.div variants={item} className="chart-grid">
                <div className="chart-card">
                    <h3>Weekly Alert Trend</h3>
                    <ResponsiveContainer width="100%" height={280}>
                        <AreaChart data={weeklyTrend}>
                            <defs>
                                <linearGradient id="aGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="rGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis dataKey="day" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Area type="monotone" dataKey="alerts" stroke="#06b6d4" fill="url(#aGrad)" strokeWidth={2} name="Alerts" />
                            <Area type="monotone" dataKey="resolved" stroke="#10b981" fill="url(#rGrad)" strokeWidth={2} name="Resolved" />
                            <Legend wrapperStyle={{ fontSize: 12 }} />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                <div className="chart-card">
                    <h3>Response Time Trend (min)</h3>
                    <ResponsiveContainer width="100%" height={280}>
                        <LineChart data={weeklyTrend}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis dataKey="day" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Line type="monotone" dataKey="mttr" stroke="#f59e0b" strokeWidth={2} dot={{ fill: '#f59e0b', r: 4 }} name="MTTR (min)" />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </motion.div>

            {/* Analyst Metrics */}
            <motion.div variants={item} className="card" style={{ marginTop: 20 }}>
                <div className="card-header">
                    <h3><Users size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />Analyst Performance</h3>
                </div>
                <div className="card-body">
                    {analysts.length === 0 ? (
                        <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 20 }}>No analyst data available yet. Metrics appear once analysts resolve alerts.</p>
                    ) : (
                        <table className="data-table">
                            <thead><tr><th>Analyst</th><th>Resolved (7d)</th><th>Avg Response</th><th>Escalated</th><th>Performance</th></tr></thead>
                            <tbody>
                                {analysts.map((a, i) => (
                                    <motion.tr key={a.name} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 + i * 0.1 }}>
                                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.name}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)' }}>{a.resolved}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)' }}>{a.avgTimeMinutes}m</td>
                                        <td style={{ fontFamily: 'var(--font-mono)', color: a.escalated > 3 ? 'var(--amber-400)' : 'var(--text-secondary)' }}>{a.escalated}</td>
                                        <td>
                                            <div style={{ background: 'var(--bg-deep)', borderRadius: 6, height: 8, width: 120, overflow: 'hidden' }}>
                                                <motion.div
                                                    style={{ height: '100%', borderRadius: 6, background: `linear-gradient(90deg, var(--cyan-500), var(--green-400))` }}
                                                    initial={{ width: 0 }}
                                                    animate={{ width: `${Math.min((a.resolved / 50) * 100, 100)}%` }}
                                                    transition={{ delay: 0.8 + i * 0.15, duration: 0.8 }}
                                                />
                                            </div>
                                        </td>
                                    </motion.tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </motion.div>
        </motion.div>
    );
}
