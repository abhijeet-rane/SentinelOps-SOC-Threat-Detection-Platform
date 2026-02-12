import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    FileSearch, Plus, ChevronDown, ChevronUp, Clock, MessageSquare,
    Paperclip, Loader2, RefreshCw, AlertTriangle, Shield
} from 'lucide-react';
import { api } from '../api';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.06 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

function IncidentCard({ incident, onRefresh }) {
    const [expanded, setExpanded] = useState(false);
    const [note, setNote] = useState('');
    const [timeline, setTimeline] = useState([]);
    const [addingNote, setAddingNote] = useState(false);

    useEffect(() => {
        if (expanded && incident.id) {
            api.getTimeline(incident.id).then(res => {
                if (res?.success && Array.isArray(res.data)) setTimeline(res.data);
            }).catch(() => { });
        }
    }, [expanded, incident.id]);

    const handleAddNote = async () => {
        if (!note.trim()) return;
        setAddingNote(true);
        await api.addNote(incident.id, note);
        setNote('');
        setAddingNote(false);
        onRefresh();
    };

    return (
        <motion.div variants={item} className="card" style={{ marginBottom: 12 }}>
            <div style={{ padding: 18 }}>
                <div className="flex items-center justify-between" style={{ cursor: 'pointer' }} onClick={() => setExpanded(!expanded)}>
                    <div className="flex items-center gap-md">
                        <span className={`severity-badge ${(incident.severity || '').toLowerCase()}`}>{incident.severity}</span>
                        <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.92rem' }}>{incident.title}</div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                                {incident.status} · Created {incident.createdAt ? new Date(incident.createdAt).toLocaleString() : '—'}
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center gap-md">
                        <span className={`status-badge ${(incident.status || '').toLowerCase()}`}>{incident.status}</span>
                        {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </div>
                </div>

                <AnimatePresence>
                    {expanded && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                            style={{ marginTop: 16, borderTop: '1px solid var(--border-default)', paddingTop: 14 }}>
                            {incident.description && (
                                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 14 }}>{incident.description}</div>
                            )}

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
                                {incident.rootCause && (
                                    <div style={{ background: 'var(--bg-deep)', padding: 10, borderRadius: 8 }}>
                                        <div style={{ fontWeight: 600, fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>ROOT CAUSE</div>
                                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{incident.rootCause}</div>
                                    </div>
                                )}
                                {incident.impactAssessment && (
                                    <div style={{ background: 'var(--bg-deep)', padding: 10, borderRadius: 8 }}>
                                        <div style={{ fontWeight: 600, fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>IMPACT</div>
                                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{incident.impactAssessment}</div>
                                    </div>
                                )}
                            </div>

                            {/* Timeline */}
                            {timeline.length > 0 && (
                                <div style={{ marginBottom: 14 }}>
                                    <h4 style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 8 }}>
                                        <Clock size={12} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />Timeline
                                    </h4>
                                    <div style={{ borderLeft: '2px solid var(--border-default)', marginLeft: 8, paddingLeft: 16 }}>
                                        {timeline.map((entry, i) => (
                                            <div key={i} style={{ marginBottom: 10, position: 'relative' }}>
                                                <div style={{
                                                    position: 'absolute', left: -22, top: 4, width: 8, height: 8,
                                                    borderRadius: '50%', background: 'var(--cyan-400)'
                                                }} />
                                                <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                                    {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '—'}
                                                </div>
                                                <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>{entry.content || entry.action || '—'}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Add Note */}
                            <div style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8 }}>
                                <div className="flex gap-sm">
                                    <input type="text" className="form-input" placeholder="Add analyst note..."
                                        style={{ flex: 1 }} value={note} onChange={e => setNote(e.target.value)}
                                        onKeyDown={e => e.key === 'Enter' && handleAddNote()} />
                                    <button className="btn btn-primary btn-sm" onClick={handleAddNote} disabled={addingNote}>
                                        {addingNote ? <Loader2 size={14} className="spin" /> : <MessageSquare size={14} />} Add
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </motion.div>
    );
}

export default function Incidents() {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.getIncidents({ pageSize: 20 });
            if (res?.success && res?.data) {
                const items = Array.isArray(res.data) ? res.data : (res.data.items || []);
                setIncidents(items);
            }
        } catch (err) {
            console.error('Failed to load incidents:', err);
        }
        setLoading(false);
    }, []);

    useEffect(() => { load(); }, [load]);

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Incident Management</h2>
                    <p>Track, investigate, and resolve security incidents</p>
                </div>
                <div className="flex gap-sm">
                    <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={14} /> Refresh</button>
                </div>
            </motion.div>

            {loading ? (
                <div style={{ textAlign: 'center', padding: 40 }}>
                    <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                    <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Loading incidents...</div>
                </div>
            ) : incidents.length === 0 ? (
                <motion.div variants={item} style={{ textAlign: 'center', padding: 40 }}>
                    <Shield size={32} style={{ color: 'var(--green-400)', marginBottom: 8 }} />
                    <div style={{ color: 'var(--text-muted)' }}>No incidents found.</div>
                </motion.div>
            ) : (
                incidents.map(inc => (
                    <IncidentCard key={inc.id} incident={inc} onRefresh={load} />
                ))
            )}
        </motion.div>
    );
}
