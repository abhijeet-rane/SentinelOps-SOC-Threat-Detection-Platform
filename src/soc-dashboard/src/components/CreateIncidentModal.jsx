import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, FileSearch, AlertTriangle, Loader2 } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastContext';

export default function CreateIncidentModal({ alert, onClose, onCreated }) {
    const toast = useToast();
    const [title, setTitle] = useState(`Security Incident: ${alert?.title || ''}`);
    const [description, setDescription] = useState(alert?.description || '');
    const [severity, setSeverity] = useState(alert?.severity || 'Medium');
    const [submitting, setSubmitting] = useState(false);

    if (!alert) return null;

    const handleSubmit = async () => {
        if (!title.trim()) {
            toast.error('Title is required');
            return;
        }
        setSubmitting(true);
        try {
            const res = await api.createIncident({
                title,
                description,
                severity,
                alertIds: [alert.id],
            });
            if (res?.success) {
                toast.success('Incident created successfully');
                if (onCreated) onCreated();
                onClose();
            } else {
                toast.error(res?.message || 'Failed to create incident');
            }
        } catch {
            toast.error('Failed to create incident');
        }
        setSubmitting(false);
    };

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 110, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                onClick={onClose}
            >
                <motion.div
                    initial={{ scale: 0.92, opacity: 0, y: 30 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.92, opacity: 0, y: 30 }}
                    transition={{ type: 'spring', damping: 22, stiffness: 300 }}
                    className="card" style={{ width: 500, maxHeight: '80vh', overflow: 'auto' }}
                    onClick={e => e.stopPropagation()}
                >
                    {/* Header */}
                    <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div className="flex items-center gap-sm">
                            <FileSearch size={18} style={{ color: 'var(--purple-400)' }} />
                            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>Create Incident from Alert</h3>
                        </div>
                        <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={18} /></button>
                    </div>

                    <div className="card-body" style={{ padding: '16px 20px' }}>
                        {/* Source Alert Info */}
                        <div style={{ marginBottom: 16, padding: 12, borderRadius: 8, background: 'rgba(168,85,247,0.06)', border: '1px solid rgba(168,85,247,0.15)' }}>
                            <div style={{ fontSize: '0.72rem', color: 'var(--purple-400)', fontWeight: 700, marginBottom: 6, textTransform: 'uppercase' }}>Source Alert</div>
                            <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>{alert.title}</div>
                            <div className="flex gap-sm items-center" style={{ flexWrap: 'wrap' }}>
                                <span className={`severity-badge ${(alert.severity || '').toLowerCase()}`}>{alert.severity}</span>
                                {alert.mitreTechnique && (
                                    <span style={{ background: 'rgba(168,85,247,0.12)', color: 'var(--purple-400)', padding: '2px 8px', borderRadius: 4, fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                                        {alert.mitreTechnique}
                                    </span>
                                )}
                            </div>
                        </div>

                        {/* Title */}
                        <div style={{ marginBottom: 14 }}>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                Title
                            </label>
                            <input
                                className="form-input"
                                value={title}
                                onChange={e => setTitle(e.target.value)}
                                style={{ width: '100%' }}
                            />
                        </div>

                        {/* Description */}
                        <div style={{ marginBottom: 14 }}>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                Description
                            </label>
                            <textarea
                                className="form-input"
                                rows={4}
                                value={description}
                                onChange={e => setDescription(e.target.value)}
                                style={{ width: '100%', resize: 'vertical' }}
                            />
                        </div>

                        {/* Severity */}
                        <div style={{ marginBottom: 14 }}>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                Severity
                            </label>
                            <select
                                className="form-select"
                                value={severity}
                                onChange={e => setSeverity(e.target.value)}
                                style={{ width: '100%' }}
                            >
                                <option value="Critical">Critical</option>
                                <option value="High">High</option>
                                <option value="Medium">Medium</option>
                                <option value="Low">Low</option>
                            </select>
                        </div>

                        {/* Buttons */}
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-default)' }}>
                            <button className="btn btn-ghost btn-sm" onClick={onClose} disabled={submitting}>
                                Cancel
                            </button>
                            <button className="btn btn-primary btn-sm" onClick={handleSubmit} disabled={submitting}>
                                {submitting ? <><Loader2 size={14} className="spin" /> Creating...</> : <><FileSearch size={14} /> Create Incident</>}
                            </button>
                        </div>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}
