import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Zap, Play, CheckCircle, XCircle, Clock, AlertTriangle, Shield, Loader } from 'lucide-react';
import { api } from '../api';
import { useToast } from '../components/ToastContext';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.06 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

export default function Playbooks() {
    const [playbooks, setPlaybooks] = useState([]);
    const [pending, setPending] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [actionLoading, setActionLoading] = useState(null);
    const toast = useToast();

    const fetchData = async () => {
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
    };

    useEffect(() => {
        const timer = setTimeout(() => {
            fetchData();
        }, 0);
        return () => clearTimeout(timer);
    }, []);

    const handleApprove = async (id) => {
        setActionLoading(id);
        await api.approveExecution(id);
        toast.success('Execution approved');
        await fetchData();
        setActionLoading(null);
    };

    const handleReject = async (id) => {
        setActionLoading(id);
        await api.rejectExecution(id, 'Rejected by analyst');
        toast.warning('Execution rejected');
        await fetchData();
        setActionLoading(null);
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center" style={{ height: '60vh' }}>
                <Loader className="spin" size={32} style={{ color: 'var(--cyan-400)' }} />
            </div>
        );
    }

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>SOAR Playbooks</h2>
                    <p>Automated response orchestration and approval workflow</p>
                </div>
            </motion.div>

            {error && <div className="login-error">{error}</div>}

            {/* Pending Approvals */}
            {pending.length > 0 && (
                <motion.div variants={item} className="card glow-border-red" style={{ marginBottom: 20 }}>
                    <div className="card-header">
                        <h3 style={{ color: 'var(--amber-400)' }}>
                            <AlertTriangle size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />
                            Pending Approvals ({pending.length})
                        </h3>
                    </div>
                    <div className="card-body" style={{ padding: 0 }}>
                        <table className="data-table">
                            <thead><tr><th>Playbook</th><th>Alert</th><th>Status</th><th>Requested</th><th>Actions</th></tr></thead>
                            <tbody>
                                {pending.map((pa) => (
                                    <tr key={pa.id}>
                                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{pa.playbookName || pa.playbook}</td>
                                        <td>{pa.alertTitle || pa.alert || 'N/A'}</td>
                                        <td><span className="severity-badge critical">{pa.status || 'Pending'}</span></td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {pa.executedAt ? new Date(pa.executedAt).toLocaleString() : pa.created || 'N/A'}
                                        </td>
                                        <td>
                                            <div className="flex gap-sm">
                                                <motion.button
                                                    className="btn btn-primary btn-sm"
                                                    whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
                                                    onClick={() => handleApprove(pa.id)}
                                                    disabled={actionLoading === pa.id}
                                                >
                                                    {actionLoading === pa.id ? <Loader className="spin" size={13} /> : <CheckCircle size={13} />}
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

            {/* Playbook Cards */}
            {playbooks.length === 0 && !loading && (
                <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                    No playbooks configured yet.
                </div>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 16 }}>
                {playbooks.map((pb, i) => (
                    <motion.div key={pb.id} variants={item} className="card" style={{ position: 'relative' }}>
                        <div style={{ padding: 22 }}>
                            <div className="flex items-center justify-between" style={{ marginBottom: 16 }}>
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
                                <div style={{
                                    padding: '3px 10px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600,
                                    background: pb.isActive ? 'rgba(16,185,129,0.12)' : 'rgba(100,116,139,0.12)',
                                    color: pb.isActive ? 'var(--green-400)' : 'var(--text-muted)',
                                }}>
                                    {pb.isActive ? 'Active' : 'Disabled'}
                                </div>
                            </div>

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
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem' }}>{pb.totalExecutions ?? pb.total ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Total</span></div>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem', color: 'var(--green-400)' }}>{pb.completedExecutions ?? pb.completed ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Success</span></div>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem', color: 'var(--red-400)' }}>{pb.failedExecutions ?? pb.failed ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Failed</span></div>
                                <div><span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1.1rem', color: 'var(--amber-400)' }}>{pb.pendingExecutions ?? pb.pending ?? 0}</span><br /><span style={{ color: 'var(--text-muted)' }}>Pending</span></div>
                            </div>

                            {/* Success Rate Bar */}
                            <div style={{ marginTop: 14 }}>
                                {(() => {
                                    const total = pb.totalExecutions ?? pb.total ?? 0;
                                    const completed = pb.completedExecutions ?? pb.completed ?? 0;
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
        </motion.div>
    );
}
