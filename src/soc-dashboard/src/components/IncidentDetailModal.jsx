import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    X, Edit3, Save, Clock, MessageSquare, Paperclip, FileSearch, Shield,
    User, AlertTriangle, Loader2, ChevronRight, Plus
} from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastContext';

const STATUSES = ['Open', 'Investigating', 'Containment', 'Eradication', 'Recovery', 'Resolved', 'Closed'];
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];
const SEV_LABELS = { Critical: 3, High: 2, Medium: 1, Low: 0 };

const TABS = [
    { key: 'overview', label: 'Overview', icon: FileSearch },
    { key: 'timeline', label: 'Timeline', icon: Clock },
    { key: 'notes', label: 'Notes', icon: MessageSquare },
    { key: 'evidence', label: 'Evidence', icon: Paperclip },
];

const TYPE_COLORS = {
    Alert: 'var(--cyan-400)',
    Note: 'var(--purple-400)',
    Evidence: 'var(--amber-400)',
    StatusChange: 'var(--green-400)',
};

export default function IncidentDetailModal({ incidentId, onClose, onUpdate }) {
    const toast = useToast();

    const [incident, setIncident] = useState(null);
    const [loading, setLoading] = useState(false);
    const [tab, setTab] = useState('overview');
    const [editMode, setEditMode] = useState(false);
    const [editForm, setEditForm] = useState({ title: '', description: '', severity: 0, rootCause: '', impactAssessment: '' });
    const [statusValue, setStatusValue] = useState(0);
    const [assigneeId, setAssigneeId] = useState('');
    const [users, setUsers] = useState([]);
    const [noteText, setNoteText] = useState('');
    const [evidenceForm, setEvidenceForm] = useState({ fileName: '', fileType: '', hash: '', fileSizeBytes: '' });
    const [saving, setSaving] = useState(false);

    const fetchDetail = useCallback(async () => {
        if (!incidentId) return;
        setLoading(true);
        try {
            const res = await api.getIncident(incidentId);
            if (res?.success && res.data) {
                setIncident(res.data);
                const sevIdx = SEVERITIES.findIndex(s => s.toLowerCase() === (res.data.severity || '').toLowerCase());
                setStatusValue(STATUSES.findIndex(s => s.toLowerCase() === (res.data.status || '').toLowerCase().replace(/\s/g, '')) || 0);
                setAssigneeId(res.data.assignedAnalystId || '');
                setEditForm({
                    title: res.data.title || '',
                    description: res.data.description || '',
                    severity: sevIdx >= 0 ? sevIdx : 0,
                    rootCause: res.data.rootCause || '',
                    impactAssessment: res.data.impactAssessment || '',
                });
            }
        } catch (err) {
            console.error('Failed to load incident:', err);
        }
        setLoading(false);
    }, [incidentId]);

    useEffect(() => {
        if (incidentId) {
            const timer = setTimeout(() => { fetchDetail(); }, 0);
            return () => clearTimeout(timer);
        }
        // Reset state when incident changes
        return () => {
            setTab('overview');
            setEditMode(false);
            setNoteText('');
            setEvidenceForm({ fileName: '', fileType: '', hash: '', fileSizeBytes: '' });
        };
    }, [incidentId, fetchDetail]);

    useEffect(() => {
        api.getUsers().then(res => {
            if (res?.success && res.data) setUsers(Array.isArray(res.data) ? res.data : []);
        }).catch(() => {});
    }, []);

    /* ── Actions ── */
    const handleStatusUpdate = async () => {
        setSaving(true);
        try {
            const res = await api.updateIncident(incidentId, { status: statusValue });
            if (res?.success) {
                toast.success(`Status updated to ${STATUSES[statusValue]}`);
                fetchDetail();
                if (onUpdate) onUpdate();
            } else {
                toast.error(res?.message || 'Failed to update status');
            }
        } catch { toast.error('Failed to update status'); }
        setSaving(false);
    };

    const handleAssign = async () => {
        if (!assigneeId) return;
        setSaving(true);
        try {
            const res = await api.updateIncident(incidentId, { assignedAnalystId: assigneeId });
            if (res?.success) {
                toast.success('Analyst assigned');
                fetchDetail();
                if (onUpdate) onUpdate();
            } else {
                toast.error(res?.message || 'Failed to assign analyst');
            }
        } catch { toast.error('Failed to assign analyst'); }
        setSaving(false);
    };

    const handleSaveEdit = async () => {
        setSaving(true);
        try {
            const res = await api.updateIncident(incidentId, {
                title: editForm.title,
                description: editForm.description,
                severity: editForm.severity,
                rootCause: editForm.rootCause,
                impactAssessment: editForm.impactAssessment,
            });
            if (res?.success) {
                toast.success('Incident updated');
                setEditMode(false);
                fetchDetail();
                if (onUpdate) onUpdate();
            } else {
                toast.error(res?.message || 'Failed to update incident');
            }
        } catch { toast.error('Failed to update incident'); }
        setSaving(false);
    };

    const handleAddNote = async () => {
        if (!noteText.trim()) return;
        setSaving(true);
        try {
            const res = await api.addNote(incidentId, noteText);
            if (res?.success) {
                toast.success('Note added');
                setNoteText('');
                fetchDetail();
            } else {
                toast.error(res?.message || 'Failed to add note');
            }
        } catch { toast.error('Failed to add note'); }
        setSaving(false);
    };

    const handleAddEvidence = async () => {
        if (!evidenceForm.fileName.trim()) return;
        setSaving(true);
        try {
            const res = await api.addEvidence(incidentId, {
                fileName: evidenceForm.fileName,
                fileType: evidenceForm.fileType,
                hash: evidenceForm.hash,
                fileSizeBytes: Number(evidenceForm.fileSizeBytes) || 0,
                storagePath: 'local',
            });
            if (res?.success) {
                toast.success('Evidence uploaded');
                setEvidenceForm({ fileName: '', fileType: '', hash: '', fileSizeBytes: '' });
                fetchDetail();
            } else {
                toast.error(res?.message || 'Failed to upload evidence');
            }
        } catch { toast.error('Failed to upload evidence'); }
        setSaving(false);
    };

    /* ── Render Helpers ── */
    const fmtDate = (d) => d ? new Date(d).toLocaleString() : '—';

    const renderOverview = () => {
        if (!incident) return null;
        const fields = [
            { label: 'Severity', value: incident.severity },
            { label: 'Status', value: incident.status },
            { label: 'Assigned Analyst', value: incident.assignedAnalystName || '—' },
            { label: 'Alert Count', value: incident.alertCount ?? 0 },
            { label: 'Created', value: fmtDate(incident.createdAt) },
            { label: 'Updated', value: fmtDate(incident.updatedAt) },
            { label: 'Resolved', value: fmtDate(incident.resolvedAt) },
            { label: 'Closed', value: fmtDate(incident.closedAt) },
        ];
        return (
            <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                    {fields.map(f => (
                        <div key={f.label} style={{ background: 'var(--bg-deep)', padding: 10, borderRadius: 8 }}>
                            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>{f.label}</div>
                            <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>{f.value}</div>
                        </div>
                    ))}
                </div>

                {incident.rootCause && (
                    <div style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8, marginBottom: 10 }}>
                        <div style={{ fontWeight: 600, fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase' }}>Root Cause</div>
                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{incident.rootCause}</div>
                    </div>
                )}
                {incident.impactAssessment && (
                    <div style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8, marginBottom: 10 }}>
                        <div style={{ fontWeight: 600, fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase' }}>Impact Assessment</div>
                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{incident.impactAssessment}</div>
                    </div>
                )}

                {/* Linked Alerts */}
                {incident.alerts && incident.alerts.length > 0 && (
                    <div style={{ marginTop: 14 }}>
                        <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>
                            <AlertTriangle size={12} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />Linked Alerts ({incident.alerts.length})
                        </div>
                        <div style={{ overflowX: 'auto' }}>
                            <table className="data-table">
                                <thead>
                                    <tr><th>Title</th><th>Severity</th><th>Status</th><th>Source IP</th><th>Created</th></tr>
                                </thead>
                                <tbody>
                                    {incident.alerts.map(a => (
                                        <tr key={a.id}>
                                            <td style={{ fontWeight: 600, fontSize: '0.82rem', color: 'var(--text-primary)' }}>{a.title}</td>
                                            <td><span className={`severity-badge ${(a.severity || '').toLowerCase()}`}>{a.severity}</span></td>
                                            <td><span className={`status-badge ${(a.status || '').toLowerCase().replace(/\s/g, '')}`}>{a.status}</span></td>
                                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{a.sourceIP || '—'}</td>
                                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{fmtDate(a.createdAt)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </>
        );
    };

    const renderTimeline = () => {
        const entries = incident?.timeline || [];
        if (entries.length === 0) {
            return <div style={{ textAlign: 'center', padding: 30, color: 'var(--text-muted)' }}>No timeline entries yet.</div>;
        }
        return (
            <div style={{ borderLeft: '2px solid var(--border-default)', marginLeft: 10, paddingLeft: 18 }}>
                {entries.map((entry, i) => {
                    const typeLabel = entry.type || entry.action || 'Event';
                    const color = TYPE_COLORS[typeLabel] || 'var(--cyan-400)';
                    return (
                        <div key={i} style={{ marginBottom: 16, position: 'relative' }}>
                            <div style={{
                                position: 'absolute', left: -24, top: 4, width: 10, height: 10,
                                borderRadius: '50%', background: color,
                            }} />
                            <div className="flex items-center gap-sm" style={{ marginBottom: 2 }}>
                                <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                    {fmtDate(entry.timestamp)}
                                </span>
                                <span style={{
                                    fontSize: '0.65rem', fontWeight: 700, padding: '1px 8px', borderRadius: 10,
                                    background: `${color}20`, color: color,
                                }}>
                                    {typeLabel}
                                </span>
                            </div>
                            <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                                {entry.description || entry.content || entry.action || '—'}
                            </div>
                            {entry.actor && (
                                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2 }}>
                                    <User size={10} style={{ display: 'inline', verticalAlign: -1, marginRight: 4 }} />{entry.actor}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        );
    };

    const renderNotes = () => {
        const notes = incident?.notes || [];
        return (
            <>
                {notes.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>No notes yet.</div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 14 }}>
                        {notes.map((n, i) => (
                            <div key={n.id || i} style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8 }}>
                                <div className="flex items-center justify-between" style={{ marginBottom: 4 }}>
                                    <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--purple-400)' }}>
                                        <User size={11} style={{ display: 'inline', verticalAlign: -1, marginRight: 4 }} />
                                        {n.authorName || n.author || 'Analyst'}
                                    </span>
                                    <span style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                        {fmtDate(n.createdAt || n.timestamp)}
                                    </span>
                                </div>
                                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{n.content}</div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Add Note */}
                <div style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8 }}>
                    <div className="flex gap-sm">
                        <input type="text" className="form-input" placeholder="Add analyst note..."
                            style={{ flex: 1 }} value={noteText} onChange={e => setNoteText(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && handleAddNote()} />
                        <button className="btn btn-primary btn-sm" onClick={handleAddNote} disabled={saving || !noteText.trim()}>
                            {saving ? <Loader2 size={14} className="spin" /> : <Plus size={14} />} Add Note
                        </button>
                    </div>
                </div>
            </>
        );
    };

    const renderEvidence = () => {
        const evidence = incident?.evidence || [];
        return (
            <>
                {evidence.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>No evidence attached.</div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                        {evidence.map((e, i) => (
                            <div key={e.id || i} style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8 }}>
                                <div className="flex items-center justify-between" style={{ marginBottom: 4 }}>
                                    <span style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                                        <Paperclip size={12} style={{ display: 'inline', verticalAlign: -1, marginRight: 6 }} />
                                        {e.fileName}
                                    </span>
                                    <span style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                        {fmtDate(e.uploadedAt)}
                                    </span>
                                </div>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
                                    <span>Type: <strong style={{ color: 'var(--text-secondary)' }}>{e.fileType || '—'}</strong></span>
                                    <span>Size: <strong style={{ color: 'var(--text-secondary)' }}>{e.fileSizeBytes != null ? `${e.fileSizeBytes} B` : '—'}</strong></span>
                                    <span style={{ gridColumn: '1 / -1' }}>SHA256: <strong style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>{e.hash || '—'}</strong></span>
                                    {e.uploadedBy && <span>Uploaded by: <strong style={{ color: 'var(--text-secondary)' }}>{e.uploadedBy}</strong></span>}
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Upload Evidence */}
                <div style={{ background: 'var(--bg-deep)', padding: 14, borderRadius: 8 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase' }}>Upload Evidence</div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                        <div>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>File Name</label>
                            <input className="form-input" value={evidenceForm.fileName}
                                onChange={e => setEvidenceForm(p => ({ ...p, fileName: e.target.value }))} />
                        </div>
                        <div>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>File Type</label>
                            <input className="form-input" value={evidenceForm.fileType}
                                onChange={e => setEvidenceForm(p => ({ ...p, fileType: e.target.value }))} />
                        </div>
                        <div>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>SHA256 Hash</label>
                            <input className="form-input" value={evidenceForm.hash}
                                onChange={e => setEvidenceForm(p => ({ ...p, hash: e.target.value }))} />
                        </div>
                        <div>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>File Size (bytes)</label>
                            <input className="form-input" type="number" value={evidenceForm.fileSizeBytes}
                                onChange={e => setEvidenceForm(p => ({ ...p, fileSizeBytes: e.target.value }))} />
                        </div>
                    </div>
                    <button className="btn btn-primary btn-sm" style={{ marginTop: 10 }}
                        onClick={handleAddEvidence} disabled={saving || !evidenceForm.fileName.trim()}>
                        {saving ? <Loader2 size={14} className="spin" /> : <Paperclip size={14} />} Upload Evidence
                    </button>
                </div>
            </>
        );
    };

    return (
        <AnimatePresence>
            {incidentId && (
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
                        className="card" style={{ width: 700, maxHeight: '85vh', overflow: 'auto' }}
                        onClick={e => e.stopPropagation()}
                    >
                        {loading ? (
                            <div style={{ padding: 60, textAlign: 'center' }}>
                                <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                                <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Loading incident...</div>
                            </div>
                        ) : incident ? (
                            <>
                                {/* ── Header ── */}
                                <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                                    <div style={{ flex: 1 }}>
                                        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 6, color: 'var(--text-primary)' }}>
                                            {incident.title}
                                        </h3>
                                        <div className="flex items-center gap-sm">
                                            <span className={`severity-badge ${(incident.severity || '').toLowerCase()}`}>{incident.severity}</span>
                                            <span className={`status-badge ${(incident.status || '').toLowerCase().replace(/\s/g, '')}`}>{incident.status}</span>
                                        </div>
                                    </div>
                                    <div className="flex gap-sm">
                                        <button className="btn btn-ghost btn-sm" onClick={() => setEditMode(!editMode)}
                                            title={editMode ? 'Cancel edit' : 'Edit incident'}
                                            style={{ color: editMode ? 'var(--amber-400)' : 'var(--text-muted)' }}>
                                            <Edit3 size={16} />
                                        </button>
                                        <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={18} /></button>
                                    </div>
                                </div>

                                {/* ── Status & Assignment Bar ── */}
                                <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border-default)', display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                                    <div style={{ flex: 1, minWidth: 140 }}>
                                        <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Status</label>
                                        <div className="flex gap-sm">
                                            <select className="form-select" style={{ flex: 1 }} value={statusValue}
                                                onChange={e => setStatusValue(Number(e.target.value))} disabled={saving}>
                                                {STATUSES.map((s, i) => <option key={s} value={i}>{s}</option>)}
                                            </select>
                                            <button className="btn btn-primary btn-sm" onClick={handleStatusUpdate} disabled={saving}>
                                                {saving ? <Loader2 size={14} className="spin" /> : <Save size={14} />} Update
                                            </button>
                                        </div>
                                    </div>
                                    <div style={{ flex: 1, minWidth: 140 }}>
                                        <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Assign Analyst</label>
                                        <div className="flex gap-sm">
                                            <select className="form-select" style={{ flex: 1 }} value={assigneeId}
                                                onChange={e => setAssigneeId(e.target.value)} disabled={saving}>
                                                <option value="">— Select —</option>
                                                {users.map(u => <option key={u.id} value={u.id}>{u.username || u.email}</option>)}
                                            </select>
                                            <button className="btn btn-ghost btn-sm" onClick={handleAssign} disabled={saving || !assigneeId}>
                                                <User size={14} /> Assign
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                {/* ── Edit Mode Panel ── */}
                                <AnimatePresence>
                                    {editMode && (
                                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                                            style={{ borderBottom: '1px solid var(--border-default)', overflow: 'hidden' }}>
                                            <div style={{ padding: '14px 20px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Title</label>
                                                    <input className="form-input" value={editForm.title}
                                                        onChange={e => setEditForm(p => ({ ...p, title: e.target.value }))} />
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Description</label>
                                                    <textarea className="form-input" rows={3} value={editForm.description}
                                                        onChange={e => setEditForm(p => ({ ...p, description: e.target.value }))} />
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Severity</label>
                                                    <select className="form-select" value={editForm.severity}
                                                        onChange={e => setEditForm(p => ({ ...p, severity: Number(e.target.value) }))}>
                                                        {SEVERITIES.map((s, i) => <option key={s} value={i}>{s}</option>)}
                                                    </select>
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Root Cause</label>
                                                    <textarea className="form-input" rows={2} value={editForm.rootCause}
                                                        onChange={e => setEditForm(p => ({ ...p, rootCause: e.target.value }))} />
                                                </div>
                                                <div>
                                                    <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Impact Assessment</label>
                                                    <textarea className="form-input" rows={2} value={editForm.impactAssessment}
                                                        onChange={e => setEditForm(p => ({ ...p, impactAssessment: e.target.value }))} />
                                                </div>
                                                <button className="btn btn-primary btn-sm" onClick={handleSaveEdit} disabled={saving} style={{ alignSelf: 'flex-start' }}>
                                                    {saving ? <Loader2 size={14} className="spin" /> : <Save size={14} />} Save Changes
                                                </button>
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>

                                {/* ── Tab Navigation ── */}
                                <div style={{ display: 'flex', gap: 4, padding: '12px 20px 0', background: 'var(--bg-elevated)', borderRadius: 0 }}>
                                    {TABS.map(({ key, label, icon: Icon }) => (
                                        <button key={key}
                                            onClick={() => setTab(key)}
                                            style={{
                                                display: 'flex', alignItems: 'center', gap: 6,
                                                padding: '8px 16px', borderRadius: '8px 8px 0 0', border: 'none', cursor: 'pointer',
                                                fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s',
                                                background: tab === key ? 'var(--cyan-500)' : 'transparent',
                                                color: tab === key ? 'white' : 'var(--text-muted)',
                                            }}>
                                            <Icon size={13} /> {label}
                                        </button>
                                    ))}
                                </div>

                                {/* ── Tab Content ── */}
                                <div className="card-body" style={{ padding: '16px 20px' }}>
                                    {tab === 'overview' && renderOverview()}
                                    {tab === 'timeline' && renderTimeline()}
                                    {tab === 'notes' && renderNotes()}
                                    {tab === 'evidence' && renderEvidence()}
                                </div>
                            </>
                        ) : (
                            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Incident not found.</div>
                        )}
                    </motion.div>
                </motion.div>
            )}
        </AnimatePresence>
    );
}
