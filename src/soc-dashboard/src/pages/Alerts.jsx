import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
    AlertTriangle, Shield, Filter, Eye, UserPlus, Loader2,
    ChevronUp, Clock, RefreshCw
} from 'lucide-react';
import { api } from '../api';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.04 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState({ page: 1, pageSize: 20 });
    const [total, setTotal] = useState(0);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.getAlerts(filter);
            if (res?.success && res?.data) {
                const items = Array.isArray(res.data) ? res.data : (res.data.items || []);
                setAlerts(items);
                setTotal(res.data.total || items.length);
            }
        } catch (err) {
            console.error('Failed to load alerts:', err);
        }
        setLoading(false);
    }, [filter]);

    useEffect(() => { load(); }, [load]);

    const updateFilter = (key, val) => setFilter(prev => ({ ...prev, [key]: val, page: 1 }));

    const handleEscalate = async (id) => {
        await api.escalateAlert(id);
        load();
    };

    const slaCheck = (alert) => {
        if (!alert.createdAt || !alert.slaDueAt) return false;
        return new Date(alert.slaDueAt) < new Date();
    };

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Alert Management</h2>
                    <p>Monitor, triage, and respond to security alerts</p>
                </div>
                <div className="flex gap-sm items-center">
                    <button className="btn btn-ghost btn-sm" onClick={load}>
                        <RefreshCw size={14} /> Refresh
                    </button>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        <strong style={{ color: 'var(--text-primary)' }}>{total}</strong> alerts
                    </span>
                </div>
            </motion.div>

            {/* Filter Bar */}
            <motion.div variants={item} className="filter-bar">
                <select className="form-select" value={filter.severity || ''} onChange={e => updateFilter('severity', e.target.value)}>
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <select className="form-select" value={filter.status || ''} onChange={e => updateFilter('status', e.target.value)}>
                    <option value="">All Statuses</option>
                    <option value="New">New</option>
                    <option value="InProgress">In Progress</option>
                    <option value="Escalated">Escalated</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Closed">Closed</option>
                </select>
                <select className="form-select" value={filter.sortBy || ''} onChange={e => updateFilter('sortBy', e.target.value)}>
                    <option value="">Newest First</option>
                    <option value="severity">By Severity</option>
                    <option value="status">By Status</option>
                </select>
            </motion.div>

            {/* Alert Table */}
            <motion.div variants={item} className="card">
                {loading ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                        <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Loading alerts...</div>
                    </div>
                ) : alerts.length === 0 ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <Shield size={32} style={{ color: 'var(--green-400)', marginBottom: 8 }} />
                        <div style={{ color: 'var(--text-muted)' }}>No alerts match the current filters.</div>
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Alert</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>MITRE</th>
                                    <th>Source IP</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alerts.map((alert, i) => {
                                    const breach = slaCheck(alert);
                                    return (
                                        <motion.tr key={alert.id}
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            transition={{ delay: i * 0.03 }}
                                            style={breach ? { boxShadow: 'inset 0 0 20px rgba(239,68,68,0.06)' } : {}}
                                        >
                                            <td>
                                                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>{alert.title}</div>
                                                {alert.description && (
                                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                        {alert.description}
                                                    </div>
                                                )}
                                                {breach && (
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 4 }}>
                                                        <Clock size={10} color="var(--red-400)" />
                                                        <span style={{ fontSize: '0.68rem', color: 'var(--red-400)', fontWeight: 600 }}>SLA BREACH</span>
                                                    </div>
                                                )}
                                            </td>
                                            <td><span className={`severity-badge ${(alert.severity || '').toLowerCase()}`}>{alert.severity}</span></td>
                                            <td><span className={`status-badge ${(alert.status || '').toLowerCase().replace(/\s/g, '')}`}>{alert.status}</span></td>
                                            <td>
                                                {alert.mitreTechnique && (
                                                    <span style={{ background: 'rgba(168,85,247,0.12)', color: 'var(--purple-400)', padding: '2px 8px', borderRadius: 4, fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                                                        {alert.mitreTechnique}
                                                    </span>
                                                )}
                                            </td>
                                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                                                {alert.sourceIP || '—'}
                                            </td>
                                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                                {alert.createdAt ? new Date(alert.createdAt).toLocaleString() : '—'}
                                            </td>
                                            <td>
                                                <div className="flex gap-sm">
                                                    <button className="btn btn-ghost btn-sm" title="View Details">
                                                        <Eye size={14} />
                                                    </button>
                                                    <button className="btn btn-ghost btn-sm" title="Escalate" onClick={() => handleEscalate(alert.id)}
                                                        style={{ color: 'var(--amber-400)' }}>
                                                        <ChevronUp size={14} />
                                                    </button>
                                                </div>
                                            </td>
                                        </motion.tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </motion.div>

            {/* Pagination */}
            {total > filter.pageSize && (
                <motion.div variants={item} className="flex justify-center gap-sm" style={{ marginTop: 16 }}>
                    <button className="btn btn-ghost btn-sm" disabled={filter.page <= 1}
                        onClick={() => setFilter(p => ({ ...p, page: p.page - 1 }))}>
                        Previous
                    </button>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: '32px' }}>
                        Page {filter.page} of {Math.ceil(total / filter.pageSize)}
                    </span>
                    <button className="btn btn-ghost btn-sm" disabled={filter.page >= Math.ceil(total / filter.pageSize)}
                        onClick={() => setFilter(p => ({ ...p, page: p.page + 1 }))}>
                        Next
                    </button>
                </motion.div>
            )}
        </motion.div>
    );
}
