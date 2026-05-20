import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    FileSearch, Plus, Eye, Loader2, RefreshCw, Shield, X, AlertTriangle
} from 'lucide-react';
import { api } from '../api';
import { useToast } from '../components/ToastContext';
import IncidentDetailModal from '../components/IncidentDetailModal';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.04 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const STATUSES = ['Open', 'Investigating', 'Containment', 'Eradication', 'Recovery', 'Resolved', 'Closed'];
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

export default function Incidents() {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState({ page: 1, pageSize: 20 });
    const [total, setTotal] = useState(0);
    const [selectedIncidentId, setSelectedIncidentId] = useState(null);
    const [showCreate, setShowCreate] = useState(false);
    const [createForm, setCreateForm] = useState({ title: '', description: '', severity: 'Critical' });
    const [creating, setCreating] = useState(false);
    const toast = useToast();

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.getIncidents({ page: filter.page, pageSize: filter.pageSize });
            if (res?.success && res?.data) {
                let items = Array.isArray(res.data) ? res.data : (res.data.items || res.data.Items || []);
                // Client-side filtering (backend GetAll only supports page/pageSize)
                if (filter.severity) items = items.filter(i => i.severity === filter.severity);
                if (filter.status) items = items.filter(i => i.status === filter.status);
                setIncidents(items);
                setTotal(res.data.totalCount || res.data.TotalCount || items.length);
            }
        } catch (err) {
            console.error('Failed to load incidents:', err);
        }
        setLoading(false);
    }, [filter]);

    useEffect(() => {
        const timer = setTimeout(() => { load(); }, 0);
        return () => clearTimeout(timer);
    }, [load]);

    const updateFilter = (key, val) => setFilter(prev => ({ ...prev, [key]: val, page: 1 }));

    const handleCreate = async () => {
        if (!createForm.title.trim()) { toast.error('Title is required'); return; }
        setCreating(true);
        try {
            const res = await api.createIncident({
                title: createForm.title,
                description: createForm.description,
                severity: createForm.severity,
                alertIds: [],
            });
            if (res?.success) {
                toast.success('Incident created');
                setShowCreate(false);
                setCreateForm({ title: '', description: '', severity: 'Critical' });
                load();
            } else {
                toast.error(res?.message || 'Failed to create incident');
            }
        } catch {
            toast.error('Failed to create incident');
        }
        setCreating(false);
    };

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            {/* Header */}
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Incident Management</h2>
                    <p>Track, investigate, and resolve security incidents</p>
                </div>
                <div className="flex gap-sm items-center">
                    <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
                        <Plus size={14} /> Create Incident
                    </button>
                    <button className="btn btn-ghost btn-sm" onClick={load}>
                        <RefreshCw size={14} /> Refresh
                    </button>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        <strong style={{ color: 'var(--text-primary)' }}>{total}</strong> incidents
                    </span>
                </div>
            </motion.div>

            {/* Filter Bar */}
            <motion.div variants={item} className="filter-bar">
                <select className="form-select" value={filter.severity || ''} onChange={e => updateFilter('severity', e.target.value)}>
                    <option value="">All Severities</option>
                    {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <select className="form-select" value={filter.status || ''} onChange={e => updateFilter('status', e.target.value)}>
                    <option value="">All Statuses</option>
                    {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
            </motion.div>

            {/* Incidents Table */}
            <motion.div variants={item} className="card">
                {loading ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                        <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Loading incidents...</div>
                    </div>
                ) : incidents.length === 0 ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <Shield size={32} style={{ color: 'var(--green-400)', marginBottom: 8 }} />
                        <div style={{ color: 'var(--text-muted)' }}>No incidents match the current filters.</div>
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Incident</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>Assigned</th>
                                    <th>Alerts</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {incidents.map((inc, i) => (
                                    <motion.tr key={inc.id}
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: i * 0.03 }}>
                                        <td>
                                            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>{inc.title}</div>
                                            {inc.description && (
                                                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                    {inc.description}
                                                </div>
                                            )}
                                        </td>
                                        <td><span className={`severity-badge ${(inc.severity || '').toLowerCase()}`}>{inc.severity}</span></td>
                                        <td><span className={`status-badge ${(inc.status || '').toLowerCase().replace(/\s/g, '')}`}>{inc.status}</span></td>
                                        <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                                            {inc.assignedAnalystName || '—'}
                                        </td>
                                        <td style={{ textAlign: 'center', fontWeight: 600, color: 'var(--text-primary)' }}>
                                            {inc.alertCount ?? 0}
                                        </td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {inc.createdAt ? new Date(inc.createdAt).toLocaleString() : '—'}
                                        </td>
                                        <td>
                                            <button className="btn btn-ghost btn-sm" title="View Details"
                                                onClick={() => setSelectedIncidentId(inc.id)}>
                                                <Eye size={14} />
                                            </button>
                                        </td>
                                    </motion.tr>
                                ))}
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

            {/* Create Incident Modal */}
            <AnimatePresence>
                {showCreate && (
                    <motion.div
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                        onClick={() => setShowCreate(false)}
                    >
                        <motion.div
                            initial={{ scale: 0.92, opacity: 0, y: 30 }}
                            animate={{ scale: 1, opacity: 1, y: 0 }}
                            exit={{ scale: 0.92, opacity: 0, y: 30 }}
                            transition={{ type: 'spring', damping: 22, stiffness: 300 }}
                            className="card" style={{ width: 480, maxHeight: '70vh', overflow: 'auto' }}
                            onClick={e => e.stopPropagation()}
                        >
                            <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                                    <FileSearch size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />Create Incident
                                </h3>
                                <button className="btn btn-ghost btn-sm" onClick={() => setShowCreate(false)}><X size={16} /></button>
                            </div>
                            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                                <div>
                                    <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Title</label>
                                    <input className="form-input" value={createForm.title} placeholder="Incident title..."
                                        onChange={e => setCreateForm(p => ({ ...p, title: e.target.value }))} />
                                </div>
                                <div>
                                    <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Description</label>
                                    <textarea className="form-input" rows={3} value={createForm.description} placeholder="Describe the incident..."
                                        onChange={e => setCreateForm(p => ({ ...p, description: e.target.value }))} />
                                </div>
                                <div>
                                    <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Severity</label>
                                    <select className="form-select" value={createForm.severity}
                                        onChange={e => setCreateForm(p => ({ ...p, severity: e.target.value }))}>
                                        <option value="Critical">Critical</option>
                                        <option value="High">High</option>
                                        <option value="Medium">Medium</option>
                                        <option value="Low">Low</option>
                                    </select>
                                </div>
                                <button className="btn btn-primary" onClick={handleCreate} disabled={creating} style={{ marginTop: 4 }}>
                                    {creating ? <Loader2 size={14} className="spin" /> : <Plus size={14} />} Create Incident
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Incident Detail Modal */}
            <IncidentDetailModal
                incidentId={selectedIncidentId}
                onClose={() => setSelectedIncidentId(null)}
                onUpdate={load}
            />
        </motion.div>
    );
}
