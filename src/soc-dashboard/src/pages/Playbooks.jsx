import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Zap, Play, CheckCircle, XCircle, Clock, AlertTriangle, Shield, Loader2,
    Plus, Eye, RefreshCw, ToggleLeft, ToggleRight, ChevronDown, ChevronUp, X, Edit3
} from 'lucide-react';
import { api } from '../api';
import { useToast } from '../components/ToastContext';
import PlaybookDetailModal from '../components/PlaybookDetailModal';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.06 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const ACTION_TYPES = ['BlockIp', 'LockAccount', 'NotifyManager', 'EscalateAlert', 'IsolateEndpoint', 'DisableUser', 'ResetCredentials', 'Custom'];

const STATUS_COLORS = {
    Pending: 'var(--amber-400)',
    Approved: 'var(--cyan-400)',
    Completed: 'var(--green-400)',
    Failed: 'var(--red-400)',
    Rejected: 'var(--text-muted)',
};

const EMPTY_CREATE_FORM = {
    name: '', description: '', actionType: 'BlockIp', actionConfig: '',
    triggerCondition: '', requiresApproval: true, isActive: true,
};

export default function Playbooks() {
    const [playbooks, setPlaybooks] = useState([]);
    const [pending, setPending] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [actionLoading, setActionLoading] = useState(null);
    const toast = useToast();

    // Create modal
    const [showCreate, setShowCreate] = useState(false);
    const [createForm, setCreateForm] = useState({ ...EMPTY_CREATE_FORM });
    const [creating, setCreating] = useState(false);

    // Detail modal
    const [selectedPlaybookId, setSelectedPlaybookId] = useState(null);

    // Execution history
    const [showHistory, setShowHistory] = useState(false);
    const [history, setHistory] = useState([]);
    const [historyTotal, setHistoryTotal] = useState(0);
    const [historyPage, setHistoryPage] = useState(1);
    const [historyLoading, setHistoryLoading] = useState(false);

    const fetchData = useCallback(async () => {
        setLoading(true);
        try {
            const [pbRes, pendRes] = await Promise.all([
                api.getPlaybooks(),
                api.getPendingExecutions()
            ]);
            if (pbRes.success) setPlaybooks(pbRes.data || []);
            if (pendRes.success) setPending(pendRes.data || []);
        } catch {
            setError('Failed to load playbooks');
        }
        setLoading(false);
    }, []);

    const fetchHistory = useCallback(async (page = 1) => {
        setHistoryLoading(true);
        try {
            const res = await api.getExecutionHistory({ page, pageSize: 10 });
            if (res?.success && res.data) {
                setHistory(res.data.items || []);
                setHistoryTotal(res.data.total || 0);
                setHistoryPage(res.data.page || page);
            }
        } catch { /* silent */ }
        setHistoryLoading(false);
    }, []);

    useEffect(() => {
        const timer = setTimeout(() => { fetchData(); }, 0);
        return () => clearTimeout(timer);
    }, [fetchData]);

    useEffect(() => {
        if (showHistory) {
            const timer = setTimeout(() => { fetchHistory(historyPage); }, 0);
            return () => clearTimeout(timer);
        }
    }, [showHistory, historyPage, fetchHistory]);

    /* ── Actions ── */
    const handleApprove = async (id) => {
        setActionLoading(id);
        try {
            await api.approveExecution(id);
            toast.success('Execution approved');
            await fetchData();
        } catch { toast.error('Failed to approve'); }
        setActionLoading(null);
    };

    const handleReject = async (id) => {
        setActionLoading(id);
        try {
            await api.rejectExecution(id, 'Rejected by analyst');
            toast.warning('Execution rejected');
            await fetchData();
        } catch { toast.error('Failed to reject'); }
        setActionLoading(null);
    };

    const handleToggle = async (pb) => {
        setActionLoading(pb.id);
        try {
            const res = await api.togglePlaybook(pb.id);
            if (res?.success) {
                const newState = res.data?.isActive ?? !pb.isActive;
                toast.success(`Playbook ${newState ? 'enabled' : 'disabled'}`);
                await fetchData();
            } else {
                toast.error(res?.message || 'Failed to toggle playbook');
            }
        } catch { toast.error('Failed to toggle playbook'); }
        setActionLoading(null);
    };

    const handleCreate = async () => {
        if (!createForm.name.trim()) { toast.error('Name is required'); return; }
        setCreating(true);
        try {
            const payload = {
                name: createForm.name,
                description: createForm.description,
                actionType: createForm.actionType,
                actionConfig: createForm.actionConfig,
                triggerCondition: createForm.triggerCondition,
                requiresApproval: createForm.requiresApproval,
                isActive: createForm.isActive,
            };
            const res = await api.createPlaybook(payload);
            if (res?.success) {
                toast.success('Playbook created');
                setShowCreate(false);
                setCreateForm({ ...EMPTY_CREATE_FORM });
                await fetchData();
            } else {
                toast.error(res?.message || 'Failed to create playbook');
            }
        } catch { toast.error('Failed to create playbook'); }
        setCreating(false);
    };

    const fmtDate = (d) => d ? new Date(d).toLocaleString() : '—';

    const historyTotalPages = Math.max(1, Math.ceil(historyTotal / 10));

    if (loading) {
        return (
            <div className="flex items-center justify-center" style={{ height: '60vh' }}>
                <Loader2 className="spin" size={32} style={{ color: 'var(--cyan-400)' }} />
            </div>
        );
    }

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            {/* ── Header ── */}
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>SOAR Playbooks</h2>
                    <p>Automated response orchestration and approval workflow · {playbooks.length} playbook{playbooks.length !== 1 ? 's' : ''}</p>
                </div>
                <div className="flex gap-sm">
                    <motion.button className="btn btn-ghost btn-sm" whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
                        onClick={() => { fetchData(); if (showHistory) fetchHistory(historyPage); }}
                        title="Refresh">
                        <RefreshCw size={16} />
                    </motion.button>
                    <motion.button className="btn btn-primary" whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
                        onClick={() => setShowCreate(true)}>
                        <Plus size={16} /> Create Playbook
                    </motion.button>
                </div>
            </motion.div>

            {error && <div className="login-error">{error}</div>}

            {/* ── Pending Approvals ── */}
            {pending.length > 0 && (
                <motion.div variants={item} className="card" style={{ marginBottom: 20, borderColor: 'var(--amber-400)', boxShadow: '0 0 20px rgba(245,158,11,0.08)' }}>
                    <div className="card-header">
                        <h3 style={{ color: 'var(--amber-400)' }}>
                            <AlertTriangle size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />
                            Pending Approvals ({pending.length})
                        </h3>
                    </div>
                    <div className="card-body" style={{ padding: 0 }}>
                        <table className="data-table">
                            <thead><tr><th>Playbook</th><th>Alert</th><th>Severity</th><th>Source / User</th><th>Requested</th><th>Actions</th></tr></thead>
                            <tbody>
                                {pending.map((pa) => (
                                    <tr key={pa.id}>
                                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{pa.playbookName || pa.playbook || 'N/A'}</td>
                                        <td style={{ fontSize: '0.82rem' }}>{pa.alertTitle || pa.alert || 'N/A'}</td>
                                        <td>
                                            {pa.alertSeverity ? (
                                                <span className={`severity-badge ${(pa.alertSeverity || '').toLowerCase()}`}>{pa.alertSeverity}</span>
                                            ) : (
                                                <span className="severity-badge critical">{pa.status || 'Pending'}</span>
                                            )}
                                        </td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {pa.sourceIP || pa.affectedUser || '—'}
                                        </td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {pa.createdAt ? new Date(pa.createdAt).toLocaleString() : pa.executedAt ? new Date(pa.executedAt).toLocaleString() : '—'}
                                        </td>
                                        <td>
                                            <div className="flex gap-sm">
                                                <motion.button
                                                    className="btn btn-primary btn-sm"
                                                    whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
                                                    onClick={() => handleApprove(pa.id)}
                                                    disabled={actionLoading === pa.id}
                                                >
                                                    {actionLoading === pa.id ? <Loader2 className="spin" size={13} /> : <CheckCircle size={13} />}
                                                    {' '}Approve
                                                </motion.button>
                                                <button
                                                    className="btn btn-danger btn-sm"
                                                    onClick={() => handleReject(pa.id)}
                                                    disabled={actionLoading === pa.id}
                                                >
                                                    <XCircle size={13} /> Reject
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </motion.div>
            )}

            {/* ── Playbook Cards ── */}
            {playbooks.length === 0 && !loading && (
                <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                    No playbooks configured yet. Click "Create Playbook" to get started.
                </div>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 16 }}>
                {playbooks.map((pb, i) => (
                    <motion.div key={pb.id} variants={item} className="card" style={{ position: 'relative' }}>
                        <div style={{ padding: 22 }}>
                            <div className="flex items-center justify-between" style={{ marginBottom: 10 }}>
                                <div className="flex items-center gap-sm">
                                    <div style={{
                                        width: 40, height: 40, borderRadius: 10,
                                        background: 'rgba(6, 182, 212, 0.12)', color: 'var(--cyan-400)',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    }}>
                                        <Zap size={20} />
                                    </div>
                                    <div>
                                        <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{pb.name}</div>
                                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{pb.actionType || pb.action}</div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-sm">
                                    <motion.button className="btn btn-ghost btn-sm" title="View details"
                                        whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}
                                        onClick={() => setSelectedPlaybookId(pb.id)}
                                        style={{ color: 'var(--cyan-400)' }}>
                                        <Eye size={16} />
                                    </motion.button>
                                    <motion.button className="btn btn-ghost btn-sm"
                                        title={pb.isActive ? 'Disable playbook' : 'Enable playbook'}
                                        whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}
                                        onClick={() => handleToggle(pb)}
                                        disabled={actionLoading === pb.id}
                                        style={{ color: pb.isActive ? 'var(--green-400)' : 'var(--text-muted)' }}>
                                        {actionLoading === pb.id ? <Loader2 size={16} className="spin" /> : pb.isActive ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                                    </motion.button>
                                </div>
                            </div>

                            {/* Description */}
                            {pb.description && (
                                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 12, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                                    {pb.description}
                                </div>
                            )}

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
                                <div style={{ background: 'var(--bg-deep)', padding: '8px 12px', borderRadius: 8, fontSize: '0.78rem' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Trigger:</span>
                                    <code style={{ marginLeft: 6, color: 'var(--cyan-400)', fontSize: '0.75rem' }}>{pb.triggerCondition || pb.trigger || 'Auto'}</code>
                                </div>
                                <div style={{ background: 'var(--bg-deep)', padding: '8px 12px', borderRadius: 8, fontSize: '0.78rem' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Approval:</span>
                                    <span style={{ marginLeft: 6, color: pb.requiresApproval ? 'var(--amber-400)' : 'var(--green-400)' }}>
                                        {pb.requiresApproval ? '🔒 Required' : '⚡ Auto'}
                                    </span>
                                </div>
                            </div>

                            {/* Execution Stats */}
                            <div className="flex gap-md" style={{ fontSize: '0.78rem' }}>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem' }}>{pb.stats?.totalExecutions ?? pb.totalExecutions ?? pb.total ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Total</span></div>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem', color: 'var(--green-400)' }}>{pb.stats?.completed ?? pb.completedExecutions ?? pb.completed ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Success</span></div>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem', color: 'var(--red-400)' }}>{pb.stats?.failed ?? pb.failedExecutions ?? pb.failed ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Failed</span></div>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem', color: 'var(--amber-400)' }}>{pb.stats?.pending ?? pb.pendingExecutions ?? pb.pending ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Pending</span></div>
                            </div>

                            {/* Success Rate Bar */}
                            <div style={{ marginTop: 14 }}>
                                {(() => {
                                    const total = pb.stats?.totalExecutions ?? pb.totalExecutions ?? pb.total ?? 0;
                                    const completed = pb.stats?.completed ?? pb.completedExecutions ?? pb.completed ?? 0;
                                    const rate = total > 0 ? Math.round((completed / total) * 100) : 0;
                                    return (
                                        <>
                                            <div style={{ background: 'var(--bg-deep)', borderRadius: 6, height: 6, overflow: 'hidden' }}>
                                                <motion.div
                                                    style={{ height: '100%', borderRadius: 6, background: 'linear-gradient(90deg, var(--green-500), var(--cyan-400))' }}
                                                    initial={{ width: 0 }}
                                                    animate={{ width: `${rate}%` }}
                                                    transition={{ delay: 0.3 + i * 0.1, duration: 0.8 }}
                                                />
                                            </div>
                                            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 4 }}>{rate}% success rate</div>
                                        </>
                                    );
                                })()}
                            </div>
                        </div>
                    </motion.div>
                ))}
            </div>

            {/* ── Execution History (Collapsible) ── */}
            <motion.div variants={item} style={{ marginTop: 24 }}>
                <motion.button
                    className="btn btn-ghost" style={{ width: '100%', justifyContent: 'space-between', padding: '12px 16px', fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)', borderRadius: 10, background: 'var(--bg-elevated)', border: '1px solid var(--border-default)' }}
                    whileHover={{ scale: 1.005 }} whileTap={{ scale: 0.995 }}
                    onClick={() => setShowHistory(!showHistory)}
                >
                    <span className="flex items-center gap-sm">
                        <Clock size={16} style={{ color: 'var(--cyan-400)' }} /> Execution History
                        {historyTotal > 0 && <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>({historyTotal} total)</span>}
                    </span>
                    {showHistory ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                </motion.button>

                <AnimatePresence>
                    {showHistory && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                            style={{ overflow: 'hidden' }}>
                            <div className="card" style={{ marginTop: 8 }}>
                                {historyLoading ? (
                                    <div style={{ padding: 30, textAlign: 'center' }}>
                                        <Loader2 className="spin" size={24} style={{ color: 'var(--cyan-400)' }} />
                                    </div>
                                ) : history.length === 0 ? (
                                    <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)' }}>No execution history yet.</div>
                                ) : (
                                    <>
                                        <div style={{ overflowX: 'auto' }}>
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Playbook</th><th>Alert</th><th>Action</th><th>Status</th>
                                                        <th>Result</th><th>Created</th><th>Completed</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {history.map(ex => {
                                                        const statusColor = STATUS_COLORS[ex.status] || 'var(--text-muted)';
                                                        return (
                                                            <tr key={ex.id}>
                                                                <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{ex.playbookName || '—'}</td>
                                                                <td style={{ fontSize: '0.82rem' }}>{ex.alertTitle || '—'}</td>
                                                                <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan-400)' }}>{ex.actionType || '—'}</span></td>
                                                                <td>
                                                                    <span style={{
                                                                        padding: '2px 10px', borderRadius: 20, fontSize: '0.68rem', fontWeight: 600,
                                                                        background: `${statusColor}18`, color: statusColor,
                                                                    }}>
                                                                        {ex.status}
                                                                    </span>
                                                                </td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                                                    title={ex.result || ex.errorMessage || ''}>
                                                                    {ex.result || ex.errorMessage || '—'}
                                                                </td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{fmtDate(ex.createdAt)}</td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{fmtDate(ex.completedAt)}</td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>

                                        {/* Pagination */}
                                        {historyTotalPages > 1 && (
                                            <div className="flex items-center justify-between" style={{ padding: '12px 16px', borderTop: '1px solid var(--border-default)' }}>
                                                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                                    Page {historyPage} of {historyTotalPages}
                                                </span>
                                                <div className="flex gap-sm">
                                                    <button className="btn btn-ghost btn-sm" disabled={historyPage <= 1}
                                                        onClick={() => setHistoryPage(p => Math.max(1, p - 1))}>
                                                        Previous
                                                    </button>
                                                    <button className="btn btn-ghost btn-sm" disabled={historyPage >= historyTotalPages}
                                                        onClick={() => setHistoryPage(p => p + 1)}>
                                                        Next
                                                    </button>
                                                </div>
                                            </div>
                                        )}
                                    </>
                                )}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </motion.div>

            {/* ── Create Playbook Modal ── */}
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
                            className="card" style={{ width: 560, maxHeight: '85vh', overflow: 'auto' }}
                            onClick={e => e.stopPropagation()}
                        >
                            <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                                    <Plus size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />
                                    Create Playbook
                                </h3>
                                <button className="btn btn-ghost btn-sm" onClick={() => setShowCreate(false)}><X size={18} /></button>
                            </div>
                            <div className="card-body" style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
                                <div>
                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Name *</label>
                                    <input className="form-input" placeholder="e.g. Block Malicious IP" value={createForm.name}
                                        onChange={e => setCreateForm(p => ({ ...p, name: e.target.value }))} />
                                </div>
                                <div>
                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Description</label>
                                    <textarea className="form-input" rows={3} placeholder="Describe what this playbook does..."
                                        value={createForm.description}
                                        onChange={e => setCreateForm(p => ({ ...p, description: e.target.value }))} />
                                </div>
                                <div>
                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Action Type</label>
                                    <select className="form-select" value={createForm.actionType}
                                        onChange={e => setCreateForm(p => ({ ...p, actionType: e.target.value }))}>
                                        {ACTION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                                    </select>
                                </div>
                                <div>
                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Action Config (optional JSON)</label>
                                    <textarea className="form-input" rows={2} value={createForm.actionConfig}
                                        style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}
                                        placeholder='e.g. {"firewallRule": "block-inbound"}'
                                        onChange={e => setCreateForm(p => ({ ...p, actionConfig: e.target.value }))} />
                                </div>
                                <div>
                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Trigger Condition (optional)</label>
                                    <input className="form-input" placeholder="e.g. severity >= High"
                                        value={createForm.triggerCondition}
                                        onChange={e => setCreateForm(p => ({ ...p, triggerCondition: e.target.value }))} />
                                </div>
                                <div className="flex gap-md">
                                    <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                        <input type="checkbox" checked={createForm.requiresApproval}
                                            onChange={e => setCreateForm(p => ({ ...p, requiresApproval: e.target.checked }))} />
                                        Requires Approval
                                    </label>
                                    <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                        <input type="checkbox" checked={createForm.isActive}
                                            onChange={e => setCreateForm(p => ({ ...p, isActive: e.target.checked }))} />
                                        Is Active
                                    </label>
                                </div>
                                <motion.button className="btn btn-primary" whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
                                    onClick={handleCreate} disabled={creating} style={{ alignSelf: 'flex-start', marginTop: 4 }}>
                                    {creating ? <Loader2 size={16} className="spin" /> : <Plus size={16} />} Create Playbook
                                </motion.button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* ── Playbook Detail Modal ── */}
            <PlaybookDetailModal
                playbookId={selectedPlaybookId}
                onClose={() => setSelectedPlaybookId(null)}
                onUpdate={fetchData}
            />
        </motion.div>
    );
}
