import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Shield, Clock, User, MapPin, ExternalLink, AlertTriangle, ChevronUp, Save } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastContext';

const SEV_COLOR = {
    Critical: 'var(--red-400)',
    High: 'var(--amber-400)',
    Medium: 'var(--cyan-400)',
    Low: 'var(--green-400)',
};

export default function AlertDetailModal({ alert, onClose, onUpdate }) {
    const [status, setStatus] = useState(alert?.status || 'New');
    const [updating, setUpdating] = useState(false);
    const toast = useToast();

    if (!alert) return null;

    const handleUpdateStatus = async () => {
        if (status === alert.status) {
            toast.info('Status unchanged');
            return;
        }

        setUpdating(true);
        try {
            const res = await api.updateAlertStatus(alert.id, status);
            if (res.success) {
                toast.success(`Alert status updated to ${status}`);
                if (onUpdate) onUpdate();
                onClose();
            } else {
                toast.error(res.message || 'Failed to update status');
            }
        } catch (err) {
            toast.error('Failed to update alert status');
        }
        setUpdating(false);
    };

    const handleEscalate = async () => {
        setUpdating(true);
        try {
            const res = await api.escalateAlert(alert.id);
            if (res.success) {
                toast.success('Alert escalated successfully');
                if (onUpdate) onUpdate();
                onClose();
            } else {
                toast.error(res.message || 'Failed to escalate alert');
            }
        } catch (err) {
            toast.error('Failed to escalate alert');
        }
        setUpdating(false);
    };

    const fields = [
        { label: 'Severity', value: alert.severity, icon: AlertTriangle, color: SEV_COLOR[alert.severity] || 'var(--text-muted)' },
        { label: 'Status', value: alert.status, icon: Clock },
        { label: 'Source IP', value: alert.sourceIP || '—', icon: MapPin },
        { label: 'Affected User', value: alert.affectedUser || '—', icon: User },
        { label: 'Affected Device', value: alert.affectedDevice || '—', icon: Shield },
        { label: 'MITRE Tactic', value: alert.mitreTactic || '—', icon: ExternalLink },
        { label: 'MITRE Technique', value: alert.mitreTechnique || '—', icon: ExternalLink },
        { label: 'Assigned To', value: alert.assignedToName || '—', icon: User },
        { label: 'Created', value: alert.createdAt ? new Date(alert.createdAt).toLocaleString() : '—', icon: Clock },
    ];

    return (
        <AnimatePresence>
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
                    className="card" style={{ width: 520, maxHeight: '80vh', overflow: 'auto' }}
                    onClick={e => e.stopPropagation()}
                >
                    {/* Header */}
                    <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 4, color: 'var(--text-primary)' }}>
                                {alert.title}
                            </h3>
                            <span className={`severity-badge ${(alert.severity || '').toLowerCase()}`}>{alert.severity}</span>
                            <span className={`status-badge ${(alert.status || '').toLowerCase()}`} style={{ marginLeft: 6 }}>{alert.status}</span>
                        </div>
                        <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={18} /></button>
                    </div>

                    {/* Details Grid */}
                    <div className="card-body" style={{ padding: '16px 20px' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                            {fields.map(f => {
                                const Icon = f.icon;
                                return (
                                    <div key={f.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Icon size={14} style={{ color: f.color || 'var(--text-muted)', flexShrink: 0 }} />
                                        <div>
                                            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{f.label}</div>
                                            <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>{f.value}</div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                        {/* Recommended Action */}
                        {alert.recommendedAction && (
                            <div style={{ marginTop: 20, padding: 14, borderRadius: 8, background: 'rgba(6,182,212,0.06)', border: '1px solid rgba(6,182,212,0.15)' }}>
                                <div style={{ fontSize: '0.72rem', color: 'var(--cyan-400)', fontWeight: 700, marginBottom: 4, textTransform: 'uppercase' }}>Recommended Action</div>
                                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{alert.recommendedAction}</div>
                            </div>
                        )}

                        {/* SLA Deadline */}
                        {alert.slaDeadline && (
                            <div style={{ marginTop: 12, fontSize: '0.78rem', color: new Date(alert.slaDeadline) < new Date() ? 'var(--red-400)' : 'var(--text-muted)' }}>
                                <Clock size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
                                SLA Deadline: {new Date(alert.slaDeadline).toLocaleString()}
                                {new Date(alert.slaDeadline) < new Date() && <span style={{ fontWeight: 700, marginLeft: 6, color: 'var(--red-400)' }}>BREACHED</span>}
                            </div>
                        )}

                        {/* Action Buttons */}
                        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-default)', display: 'flex', gap: 10 }}>
                            {/* Status Dropdown */}
                            <div style={{ flex: 1 }}>
                                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                    Update Status
                                </label>
                                <select 
                                    className="form-select" 
                                    value={status} 
                                    onChange={(e) => setStatus(e.target.value)}
                                    disabled={updating}
                                    style={{ width: '100%' }}
                                >
                                    <option value="New">New</option>
                                    <option value="InProgress">In Progress</option>
                                    <option value="Escalated">Escalated</option>
                                    <option value="Resolved">Resolved</option>
                                    <option value="Closed">Closed</option>
                                </select>
                            </div>

                            {/* Action Buttons */}
                            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
                                <button 
                                    className="btn btn-primary btn-sm" 
                                    onClick={handleUpdateStatus}
                                    disabled={updating || status === alert.status}
                                    title="Update Status"
                                >
                                    <Save size={14} />
                                    {updating ? 'Updating...' : 'Update'}
                                </button>
                                
                                {alert.status !== 'Escalated' && alert.status !== 'Resolved' && alert.status !== 'Closed' && (
                                    <button 
                                        className="btn btn-ghost btn-sm" 
                                        onClick={handleEscalate}
                                        disabled={updating}
                                        title="Escalate Alert"
                                        style={{ color: 'var(--amber-400)' }}
                                    >
                                        <ChevronUp size={14} />
                                        Escalate
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}
