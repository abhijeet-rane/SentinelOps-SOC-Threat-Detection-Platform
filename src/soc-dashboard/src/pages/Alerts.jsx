import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
    AlertTriangle, Shield, Filter, Eye, UserPlus, Loader2,
    ChevronUp, Clock, RefreshCw, XCircle, ChevronLeft, ChevronRight,
    ChevronsLeft, ChevronsRight
} from 'lucide-react';
import { api } from '../api';
import AlertDetailModal from '../components/AlertDetailModal';
import CreateIncidentModal from '../components/CreateIncidentModal';
import { useToast } from '../components/ToastContext';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.04 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const PAGE_SIZES = [10, 20, 50, 100];

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState({ page: 1, pageSize: 20 });
    const [total, setTotal] = useState(0);
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [users, setUsers] = useState([]);
    const [createIncidentAlert, setCreateIncidentAlert] = useState(null);
    const toast = useToast();

    const totalPages = Math.max(1, Math.ceil(total / filter.pageSize));

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.getAlerts(filter);
            if (res?.success && res?.data) {
                // ASP.NET Core uses camelCase by default
                const items = Array.isArray(res.data)
                    ? res.data
                    : (res.data.items || res.data.Items || []);
                setAlerts(items);
                setTotal(
                    res.data.totalCount ?? res.data.TotalCount ?? res.data.total ?? items.length
                );
            }
        } catch (err) {
            console.error('Failed to load alerts:', err);
        }
        setLoading(false);
    }, [filter]);

    useEffect(() => {
        const timer = setTimeout(() => {
            load();
        }, 0);
        return () => clearTimeout(timer);
    }, [load]);

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const res = await api.getUsers();
                if (res?.success) setUsers(res.data || []);
            } catch { /* non-admin — ignore */ }
        };
        fetchUsers();
    }, []);

    const updateFilter = (key, val) => setFilter(prev => ({ ...prev, [key]: val, page: 1 }));

    const goToPage = (p) => {
        const clamped = Math.max(1, Math.min(p, totalPages));
        setFilter(prev => ({ ...prev, page: clamped }));
    };

    const handleEscalate = async (id) => {
        await api.escalateAlert(id);
        toast.success('Alert escalated successfully');
        load();
    };

    const slaCheck = (alert) => {
        if (!alert.createdAt || !alert.slaDeadline) return false;
        return new Date(alert.slaDeadline) < new Date();
    };

    const clearFilters = () => setFilter({ page: 1, pageSize: filter.pageSize });

    // Generate visible page numbers
    const getPageNumbers = () => {
        const pages = [];
        const maxVisible = 7;
        if (totalPages <= maxVisible) {
            for (let i = 1; i <= totalPages; i++) pages.push(i);
        } else {
            pages.push(1);
            let start = Math.max(2, filter.page - 2);
            let end = Math.min(totalPages - 1, filter.page + 2);
            if (filter.page <= 3) end = Math.min(5, totalPages - 1);
            if (filter.page >= totalPages - 2) start = Math.max(totalPages - 4, 2);
            if (start > 2) pages.push('...');
            for (let i = start; i <= end; i++) pages.push(i);
            if (end < totalPages - 1) pages.push('...');
            pages.push(totalPages);
        }
        return pages;
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
            <motion.div variants={item} className="filter-bar" style={{ flexWrap: 'wrap' }}>
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
                <input
                    className="form-input"
                    placeholder="Source IP"
                    value={filter.sourceIP || ''}
                    onChange={e => updateFilter('sourceIP', e.target.value)}
                    style={{ maxWidth: 140 }}
                />
                <input
                    className="form-input"
                    placeholder="Affected User"
                    value={filter.affectedUser || ''}
                    onChange={e => updateFilter('affectedUser', e.target.value)}
                    style={{ maxWidth: 150 }}
                />
                <select className="form-select" value={filter.assignedTo || ''} onChange={e => updateFilter('assignedTo', e.target.value)} style={{ maxWidth: 160 }}>
                    <option value="">All Analysts</option>
                    {users.map(u => (
                        <option key={u.id} value={u.id}>{u.username}</option>
                    ))}
                </select>
                <input
                    className="form-input"
                    type="date"
                    title="From date"
                    value={filter.from || ''}
                    onChange={e => updateFilter('from', e.target.value)}
                    style={{ maxWidth: 145 }}
                />
                <input
                    className="form-input"
                    type="date"
                    title="To date"
                    value={filter.to || ''}
                    onChange={e => updateFilter('to', e.target.value)}
                    style={{ maxWidth: 145 }}
                />
                <label className="flex items-center gap-sm" style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
                    <input
                        type="checkbox"
                        checked={!!filter.slaBreach}
                        onChange={e => updateFilter('slaBreach', e.target.checked ? true : '')}
                    />
                    SLA Breach
                </label>
                <button className="btn btn-ghost btn-sm" onClick={clearFilters} title="Clear all filters">
                    <XCircle size={14} /> Clear
                </button>
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
                                    <th>Assigned</th>
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
                                            <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                                                {alert.assignedAnalystName || '—'}
                                            </td>
                                            <td>
                                                <div className="flex gap-sm">
                                                    <button className="btn btn-ghost btn-sm" title="View Details" onClick={() => setSelectedAlert(alert)}>
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

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <motion.div variants={item} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    marginTop: 16, padding: '12px 16px',
                    background: 'var(--bg-elevated)', borderRadius: 10,
                    border: '1px solid var(--border-default)',
                }}>
                    {/* Left: Info */}
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        Showing{' '}
                        <strong style={{ color: 'var(--text-primary)' }}>
                            {(filter.page - 1) * filter.pageSize + 1}–{Math.min(filter.page * filter.pageSize, total)}
                        </strong>
                        {' '}of{' '}
                        <strong style={{ color: 'var(--text-primary)' }}>{total}</strong>
                    </div>

                    {/* Center: Page buttons */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <button className="btn btn-ghost btn-sm" disabled={filter.page <= 1}
                            onClick={() => goToPage(1)} title="First page"
                            style={{ padding: '4px 6px' }}>
                            <ChevronsLeft size={14} />
                        </button>
                        <button className="btn btn-ghost btn-sm" disabled={filter.page <= 1}
                            onClick={() => goToPage(filter.page - 1)} title="Previous page"
                            style={{ padding: '4px 6px' }}>
                            <ChevronLeft size={14} />
                        </button>

                        {getPageNumbers().map((p, i) => (
                            p === '...'
                                ? <span key={`e${i}`} style={{ padding: '0 4px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>…</span>
                                : <button key={p}
                                    className={`btn btn-sm ${p === filter.page ? 'btn-primary' : 'btn-ghost'}`}
                                    onClick={() => goToPage(p)}
                                    style={{
                                        minWidth: 32, padding: '4px 8px',
                                        fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                                        fontWeight: p === filter.page ? 700 : 400,
                                    }}>
                                    {p}
                                </button>
                        ))}

                        <button className="btn btn-ghost btn-sm" disabled={filter.page >= totalPages}
                            onClick={() => goToPage(filter.page + 1)} title="Next page"
                            style={{ padding: '4px 6px' }}>
                            <ChevronRight size={14} />
                        </button>
                        <button className="btn btn-ghost btn-sm" disabled={filter.page >= totalPages}
                            onClick={() => goToPage(totalPages)} title="Last page"
                            style={{ padding: '4px 6px' }}>
                            <ChevronsRight size={14} />
                        </button>
                    </div>

                    {/* Right: Page size */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Per page:</span>
                        <select className="form-select" value={filter.pageSize}
                            onChange={e => setFilter(prev => ({ ...prev, pageSize: Number(e.target.value), page: 1 }))}
                            style={{ width: 70, padding: '4px 8px', fontSize: '0.8rem' }}>
                            {PAGE_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
                        </select>
                    </div>
                </motion.div>
            )}

            <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} onUpdate={load} onCreateIncident={setCreateIncidentAlert} />
            {createIncidentAlert && <CreateIncidentModal alert={createIncidentAlert} onClose={() => setCreateIncidentAlert(null)} onCreated={load} />}
        </motion.div>
    );
}
