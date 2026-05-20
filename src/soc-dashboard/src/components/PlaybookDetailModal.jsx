import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Edit3, Save, Zap, Play, Clock, Loader2, CheckCircle, AlertTriangle } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastContext';

const ACTION_TYPES = ['BlockIp', 'LockAccount', 'NotifyManager', 'EscalateAlert', 'IsolateEndpoint', 'DisableUser', 'ResetCredentials', 'Custom'];

const STATUS_COLORS = {
    Pending: 'var(--amber-400)',
    Approved: 'var(--cyan-400)',
    Completed: 'var(--green-400)',
    Failed: 'var(--red-400)',
    Rejected: 'var(--text-muted)',
};

export default function PlaybookDetailModal({ playbookId, onClose, onUpdate }) {
    const toast = useToast();

    const [playbook, setPlaybook] = useState(null);
    const [loading, setLoading] = useState(false);
    const [editMode, setEditMode] = useState(false);
    const [editForm, setEditForm] = useState({
        name: '', description: '', actionType: 'BlockIp', actionConfig: '',
        triggerCondition: '', requiresApproval: true, isActive: true,
    });
    const [saving, setSaving] = useState(false);

    // Manual trigger state
    const [triggerAlertId, setTriggerAlertId] = useState('');
    const [triggering, setTriggering] = useState(false);

    const fetchDetail = useCallback(async () => {
        if (!playbookId) return;
        setLoading(true);
        try {
            const res = await api.getPlaybook(playbookId);
            if (res?.success && res.data) {
                setPlaybook(res.data);
                setEditForm({
                    name: res.data.name || '',
                    description: res.data.description || '',
                    actionType: res.data.actionType || 'BlockIp',
                    actionConfig: typeof res.data.actionConfig === 'object'
                        ? JSON.stringify(res.data.actionConfig, null, 2)
                        : (res.data.actionConfig || ''),
                    triggerCondition: res.data.triggerCondition || '',
                    requiresApproval: !!res.data.requiresApproval,
                    isActive: !!res.data.isActive,
                });
            }
        } catch (err) {
            console.error('Failed to load playbook:', err);
        }
        setLoading(false);
    }, [playbookId]);

    useEffect(() => {
        if (playbookId) {
            const timer = setTimeout(() => { fetchDetail(); }, 0);
            return () => clearTimeout(timer);
        }
        // Reset edit mode and trigger alert ID when playbook changes
        return () => {
            setEditMode(false);
            setTriggerAlertId('');
        };
    }, [playbookId, fetchDetail]);

    const fmtDate = (d) => d ? new Date(d).toLocaleString() : '—';

    /* ── Save Edit ── */
    const handleSave = async () => {
        setSaving(true);
        try {
            const payload = {
                name: editForm.name,
                description: editForm.description,
                actionType: editForm.actionType,
                actionConfig: editForm.actionConfig,
                triggerCondition: editForm.triggerCondition,
                requiresApproval: editForm.requiresApproval,
                isActive: editForm.isActive,
            };
            const res = await api.updatePlaybook(playbookId, payload);
            if (res?.success) {
                toast.success('Playbook updated');
                setEditMode(false);
                fetchDetail();
                if (onUpdate) onUpdate();
            } else {
                toast.error(res?.message || 'Failed to update playbook');
            }
        } catch { toast.error('Failed to update playbook'); }
        setSaving(false);
    };

    /* ── Manual Trigger ── */
    const handleTrigger = async () => {
        if (!triggerAlertId.trim()) return;
        setTriggering(true);
        try {
            const res = await api.triggerPlaybook(playbookId, triggerAlertId.trim());
            if (res?.success) {
                toast.success(res.message || 'Playbook triggered');
                setTriggerAlertId('');
                fetchDetail();
            } else {
                toast.error(res?.message || 'Failed to trigger playbook');
            }
        } catch { toast.error('Failed to trigger playbook'); }
        setTriggering(false);
    };

    /* ── Render ── */
    return (
        <AnimatePresence>
            {playbookId && (
                <motion.div
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                    onClick={onClose}
                >
                    <motion.div
                        initial={{ scale: 0.92, opacity: 0, y: 30 }}
                        animate={{ scale: 1, opacity: 1, y: 0 }}
                        exit={{ scale: 0.92, opacity: 0, y: 30 }}
                        transition={{ type: 'spring', damping: 22, stiffness: 300 }}
                        className="card" style={{ width: 650, maxHeight: '85vh', overflow: 'auto' }}
                        onClick={e => e.stopPropagation()}
                    >
                        {loading ? (
                            <div style={{ padding: 60, textAlign: 'center' }}>
                                <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                                <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Loading playbook...</div>
                            </div>
                        ) : playbook ? (
                            <>
                                {/* ── Header ── */}
                                <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                                    <div style={{ flex: 1 }}>
                                        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 6, color: 'var(--text-primary)' }}>
                                            {playbook.name}
                                        </h3>
                                        <div className="flex items-center gap-sm">
                                            <span style={{
                                                padding: '2px 10px', borderRadius: 20, fontSize: '0.68rem', fontWeight: 600,
                                                background: 'rgba(6,182,212,0.12)', color: 'var(--cyan-400)',
                                            }}>
                                                {playbook.actionType}
                                            </span>
                                            <span style={{
                                                padding: '2px 10px', borderRadius: 20, fontSize: '0.68rem', fontWeight: 600,
                                                background: playbook.isActive ? 'rgba(16,185,129,0.12)' : 'rgba(100,116,139,0.12)',
                                                color: playbook.isActive ? 'var(--green-400)' : 'var(--text-muted)',
                                            }}>
                                                {playbook.isActive ? 'Active' : 'Disabled'}
                                            </span>
                                        </div>
                                    </div>
                                    <div className="flex gap-sm">
                                        <button className="btn btn-ghost btn-sm" onClick={() => setEditMode(!editMode)}
                                            title={editMode ? 'Cancel edit' : 'Edit playbook'}
                                            style={{ color: editMode ? 'var(--amber-400)' : 'var(--text-muted)' }}>
                                            <Edit3 size={16} />
                                        </button>
                                        <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={18} /></button>
                                    </div>
                                </div>

                                {/* ── Info Grid ── */}
                                <div style={{ padding: '16px 20px' }}>
                                    {playbook.description && (
                                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 14 }}>
                                            {playbook.description}
                                        </div>
                                    )}
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                                        {[
                                            { label: 'Action Type', value: playbook.actionType },
                                            { label: 'Trigger Condition', value: playbook.triggerCondition || 'Auto' },
                                            { label: 'Requires Approval', value: playbook.requiresApproval ? 'Yes' : 'No' },
                                            { label: 'Status', value: playbook.isActive ? 'Active' : 'Disabled' },
                                            { label: 'Created', value: fmtDate(playbook.createdAt) },
                                        ].map(f => (
                                            <div key={f.label} style={{ background: 'var(--bg-deep)', padding: 10, borderRadius: 8 }}>
                                                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>{f.label}</div>
                                                <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>{f.value}</div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* ActionConfig */}
                                    {playbook.actionConfig && (
                                        <div style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8, marginBottom: 16 }}>
                                            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Action Config</div>
                                            <pre style={{
                                                fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--cyan-400)',
                                                whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0,
                                                background: 'rgba(0,0,0,0.2)', padding: 10, borderRadius: 6,
                                            }}>
                                                <code>{typeof playbook.actionConfig === 'object' ? JSON.stringify(playbook.actionConfig, null, 2) : playbook.actionConfig}</code>
                                            </pre>
                                        </div>
                                    )}
                                </div>

                                {/* ── Edit Mode Panel ── */}
                                <AnimatePresence>
                                    {editMode && (
                                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                                            style={{ borderTop: '1px solid var(--border-default)', borderBottom: '1px solid var(--border-default)', overflow: 'hidden' }}>
                                            <div style={{ padding: '14px 20px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Name</label>
                                                    <input className="form-input" value={editForm.name}
                                                        onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))} />
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Description</label>
                                                    <textarea className="form-input" rows={3} value={editForm.description}
                                                        onChange={e => setEditForm(p => ({ ...p, description: e.target.value }))} />
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Action Type</label>
                                                    <select className="form-select" value={editForm.actionType}
                                                        onChange={e => setEditForm(p => ({ ...p, actionType: e.target.value }))}>
                                                        {ACTION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                                                    </select>
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Action Config</label>
                                                    <textarea className="form-input" rows={3} value={editForm.actionConfig}
                                                        style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}
                                                        onChange={e => setEditForm(p => ({ ...p, actionConfig: e.target.value }))} />
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Trigger Condition</label>
                                                    <input className="form-input" value={editForm.triggerCondition}
                                                        onChange={e => setEditForm(p => ({ ...p, triggerCondition: e.target.value }))} />
                                                </div>
                                                <div className="flex gap-md">
                                                    <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                                        <input type="checkbox" checked={editForm.requiresApproval}
                                                            onChange={e => setEditForm(p => ({ ...p, requiresApproval: e.target.checked }))} />
                                                        Requires Approval
                                                    </label>
                                                    <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                                        <input type="checkbox" checked={editForm.isActive}
                                                            onChange={e => setEditForm(p => ({ ...p, isActive: e.target.checked }))} />
                                                        Is Active
                                                    </label>
                                                </div>
                                                <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving} style={{ alignSelf: 'flex-start' }}>
                                                    {saving ? <Loader2 size={14} className="spin" /> : <Save size={14} />} Save Changes
                                                </button>
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>

                                {/* ── Manual Trigger ── */}
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-default)' }}>
                                    <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                        <Zap size={12} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />
                                        Trigger for Alert
                                    </div>
                                    <div className="flex gap-sm">
                                        <input type="text" className="form-input" style={{ flex: 1 }}
                                            placeholder="Enter Alert ID (GUID)" value={triggerAlertId}
                                            onChange={e => setTriggerAlertId(e.target.value)}
                                            onKeyDown={e => e.key === 'Enter' && handleTrigger()} />
                                        <motion.button className="btn btn-primary btn-sm"
                                            whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
                                            onClick={handleTrigger} disabled={triggering || !triggerAlertId.trim()}>
                                            {triggering ? <Loader2 size={14} className="spin" /> : <Play size={14} />} Trigger
                                        </motion.button>
                                    </div>
                                </div>

                                {/* ── Execution History ── */}
                                <div style={{ padding: '14px 20px' }}>
                                    <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                        <Clock size={12} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />
                                        Execution History
                                    </div>
                                    {(!playbook.executions || playbook.executions.length === 0) ? (
                                        <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>No executions yet</div>
                                    ) : (
                                        <div style={{ overflowX: 'auto' }}>
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Alert</th>
                                                        <th>Status</th>
                                                        <th>Result</th>
                                                        <th>Created</th>
                                                        <th>Approved</th>
                                                        <th>Executed</th>
                                                        <th>Completed</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {playbook.executions.map(ex => {
                                                        const statusColor = STATUS_COLORS[ex.status] || 'var(--text-muted)';
                                                        return (
                                                            <tr key={ex.id}>
                                                                <td style={{ fontWeight: 600, fontSize: '0.82rem', color: 'var(--text-primary)', maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                                    {ex.alertTitle || ex.alertId || '—'}
                                                                </td>
                                                                <td>
                                                                    <span style={{
                                                                        padding: '2px 10px', borderRadius: 20, fontSize: '0.68rem', fontWeight: 600,
                                                                        background: `${statusColor}18`, color: statusColor,
                                                                    }}>
                                                                        {ex.status}
                                                                    </span>
                                                                </td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                                                    title={ex.result || ex.errorMessage || ''}>
                                                                    {ex.result || ex.errorMessage || '—'}
                                                                </td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{fmtDate(ex.createdAt)}</td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{fmtDate(ex.approvedAt)}</td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{fmtDate(ex.executedAt)}</td>
                                                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{fmtDate(ex.completedAt)}</td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            </>
                        ) : (
                            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Playbook not found.</div>
                        )}
                    </motion.div>
                </motion.div>
            )}
        </AnimatePresence>
    );
}
