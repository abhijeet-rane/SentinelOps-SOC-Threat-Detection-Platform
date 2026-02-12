import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ScrollText, ShieldCheck, Loader } from 'lucide-react';
import { api } from '../api';

function getActionColor(action) {
    if (action.includes('Login') || action.includes('Logout')) return 'var(--cyan-400)';
    if (action.includes('Alert') || action.includes('Escalate')) return 'var(--amber-400)';
    if (action.includes('Incident') || action.includes('Note') || action.includes('Evidence')) return 'var(--purple-400)';
    if (action.includes('Playbook') || action.includes('Approve')) return 'var(--green-400)';
    if (action.includes('Rule') || action.includes('Toggle') || action.includes('Locked')) return 'var(--red-400)';
    return 'var(--text-secondary)';
}

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.03 } } };
const item = { hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0 } };

export default function AuditLog() {
    const [logs, setLogs] = useState([]);
    const [totalCount, setTotalCount] = useState(0);
    const [page, setPage] = useState(1);
    const [entityFilter, setEntityFilter] = useState('');
    const [loading, setLoading] = useState(true);
    const [integrity, setIntegrity] = useState(null);

    const fetchLogs = async () => {
        setLoading(true);
        const params = { page, pageSize: 25 };
        if (entityFilter) params.entity = entityFilter;
        const res = await api.getAuditLogs(params);
        if (res.success && res.data) {
            setLogs(res.data.items || []);
            setTotalCount(res.data.totalCount || 0);
        }
        setLoading(false);
    };

    useEffect(() => { fetchLogs(); }, [page, entityFilter]);

    const checkIntegrity = async () => {
        const res = await api.verifyAuditIntegrity();
        if (res.success) setIntegrity(res.data);
    };

    const totalPages = Math.ceil(totalCount / 25);

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Audit Log</h2>
                    <p>Complete audit trail of all platform actions</p>
                </div>
                <button className="btn btn-ghost btn-sm" onClick={checkIntegrity}>
                    <ShieldCheck size={14} /> Verify Integrity
                </button>
            </motion.div>

            {integrity && (
                <motion.div variants={item} className={`card ${integrity.integrityValid ? '' : 'glow-border-red'}`} style={{ marginBottom: 16, padding: '12px 20px' }}>
                    <div className="flex items-center gap-md">
                        <ShieldCheck size={18} style={{ color: integrity.integrityValid ? 'var(--green-400)' : 'var(--red-400)' }} />
                        <div>
                            <strong style={{ color: integrity.integrityValid ? 'var(--green-400)' : 'var(--red-400)' }}>
                                {integrity.integrityValid ? '✓ Hash chain integrity verified' : '⚠ Hash chain integrity broken'}
                            </strong>
                            <span style={{ marginLeft: 12, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                {integrity.totalEntries} entries checked{integrity.brokenLinks > 0 ? `, ${integrity.brokenLinks} broken links` : ''}
                            </span>
                        </div>
                    </div>
                </motion.div>
            )}

            <motion.div variants={item} className="filter-bar">
                <select className="form-select" value={entityFilter} onChange={e => { setEntityFilter(e.target.value); setPage(1); }}>
                    <option value="">All Entities</option>
                    <option value="User">Authentication</option>
                    <option value="Alert">Alerts</option>
                    <option value="Incident">Incidents</option>
                    <option value="Playbook">Playbooks</option>
                    <option value="DetectionRule">Detection Rules</option>
                    <option value="ThreatIntel">Threat Intel</option>
                </select>
                <div style={{ marginLeft: 'auto', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{totalCount}</strong> entries
                </div>
            </motion.div>

            <motion.div variants={item} className="card">
                <div className="card-body" style={{ padding: 0 }}>
                    {loading ? (
                        <div className="flex items-center justify-center" style={{ padding: 40 }}>
                            <Loader className="spin" size={24} style={{ color: 'var(--cyan-400)' }} />
                        </div>
                    ) : (
                        <table className="data-table">
                            <thead><tr><th>Timestamp</th><th>Action</th><th>User</th><th>Entity</th><th>Details</th></tr></thead>
                            <tbody>
                                {logs.length === 0 ? (
                                    <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>No audit logs found</td></tr>
                                ) : logs.map((log) => (
                                    <motion.tr key={log.id} variants={item}>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{log.timestamp}</td>
                                        <td>
                                            <span style={{ color: getActionColor(log.action), fontWeight: 600, fontSize: '0.82rem' }}>
                                                {log.action}
                                            </span>
                                        </td>
                                        <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{log.user}</td>
                                        <td>
                                            <span style={{
                                                padding: '2px 8px', borderRadius: 4, fontSize: '0.7rem', fontWeight: 600,
                                                background: 'var(--bg-elevated)', color: 'var(--text-secondary)',
                                            }}>
                                                {log.entity}
                                            </span>
                                        </td>
                                        <td style={{ fontSize: '0.82rem', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.detail}</td>
                                    </motion.tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </motion.div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-center gap-sm" style={{ marginTop: 16 }}>
                    <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Page {page} of {totalPages}</span>
                    <button className="btn btn-ghost btn-sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
                </div>
            )}
        </motion.div>
    );
}
